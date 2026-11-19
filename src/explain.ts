import { z } from "zod";
import { groupName, guestEnded, isGuest, principalFor, resolveStream, type ResolvedResource, type ResolvedStream } from "./app.js";
import { resolveSession } from "./sessions.js";
import { allGroups, check, inGroup, type CheckStep, type Op, type Principal } from "./mode.js";
import { keyUsable, type Policy } from "./policy.js";
import { matchControlRule } from "./control.js";
import { HOSTED_CLIENTS } from "./hosted-clients.js";
import type { Store } from "./store.js";

/**
 * The operator's "explain" check (docs/contract.md, "Explain"): may X do op on Y, and why. It runs the same
 * deterministic check as a real request, against the live policy or a draft, and never calls the classifier.
 */

const Gid = z.number().int().nonnegative();

export const SubjectSchema = z.union([
  /** A registered agent, looked up in relaygate's database. */
  z.object({ agent: z.string().min(1) }).strict(),
  /** A hypothetical agent enrolled with this key (optionally with this name). */
  z.object({ key: z.string().min(1), name: z.string().min(1).optional() }).strict(),
  /** A hypothetical agent with these groups. */
  z.object({ gid: Gid, groups: z.array(Gid).default([]), guest: z.boolean().default(false), name: z.string().min(1).optional() }).strict(),
  /**
   * A relay-control user, mapped through controlPrincipals. Defaults to a person on the dashboard (kind read, reader
   * browser); kind device with as agent explains the agents their desktop enrols.
   */
  z
    .object({
      control: z
        .object({
          userId: z.string().min(1),
          orgId: z.string().min(1),
          email: z.string().min(3).optional(),
          role: z.enum(["owner", "admin", "member"]).optional(),
          workspaceId: z.string().min(1).optional(),
          kind: z.enum(["device", "read", "launch", "hosted"]).default("read"),
          readerKind: z.enum(["browser", "device", "mcp"]).optional(),
          /** kind hosted only: the hosted MCP client (default "mcp"). */
          client: z.enum(HOSTED_CLIENTS).optional(),
          as: z.enum(["person", "agent"]).optional(),
        })
        .strict(),
    })
    .strict(),
]);
export type Subject = z.input<typeof SubjectSchema>;

export const QuerySchema = z.object({
  as: SubjectSchema,
  op: z.enum(["r", "w"]),
  resource: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("stream"), id: z.string().min(1) }),
    /**
     * A session: a recorded one is looked up in relaygate's database; otherwise `gid` says which group's agent
     * uploaded it first (a hypothetical session; the subject is never its owner).
     */
    z.object({ kind: z.literal("session"), id: z.string().min(1), gid: Gid.optional() }),
  ]),
});
export type Query = z.input<typeof QuerySchema>;

export const CaseSchema = QuerySchema.extend({
  /** What the operator expects: the deterministic decision, and optionally whether the classifier would run. */
  expect: z.enum(["allow", "deny"]),
  classified: z.boolean().optional(),
  note: z.string().optional(),
});
export type Case = z.input<typeof CaseSchema>;

export interface Explanation {
  decision: "allow" | "deny";
  /** Content-free reason, the same text the audit log would record. */
  reason: string;
  /** Whether the classifier would see this request (writes across a group boundary, or to a classify stream). */
  classified: boolean;
  subject: { name: string; gid: number; groups: number[]; group_names: string[]; guest: boolean };
  resource: ResolvedStream | ResolvedResource | null;
  steps: Array<CheckStep | { step: "subject" | "resource" | "classifier"; detail: string }>;
  summary: string;
}

type ResolvedSubject =
  | { ok: true; principal: Principal; name: string; guest: boolean; notes: string[] }
  | { ok: false; reason: string; detail: string };

function resolveSubject(subject: Subject, policy: Policy, store: Pick<Store, "agentByName"> | undefined, now: number): ResolvedSubject {
  const s = SubjectSchema.parse(subject);
  if ("agent" in s) {
    const agent = store?.agentByName(s.agent);
    if (!agent) return { ok: false, reason: "unknown_agent", detail: `no registered agent named ${s.agent}` };
    const ended = guestEnded(agent, policy, now);
    if (ended) return { ok: false, reason: ended, detail: `${s.agent} is a guest whose key has ended; its tokens no longer work` };
    const guest = isGuest(agent, policy);
    return { ok: true, principal: principalFor(agent, policy), name: agent.name, guest, notes: [`registered agent ${agent.name} (key ${agent.keyId})`] };
  }
  if ("key" in s) {
    const key = policy.enrollmentKeys.find((k) => k.id === s.key);
    if (!key) return { ok: false, reason: "unknown_key", detail: `no enrollment key ${s.key} in the policy` };
    if (!keyUsable(key, now)) return { ok: false, reason: key.revoked ? "key_revoked" : "key_expired", detail: `key ${key.id} can't enroll anyone` };
    const name = s.name ?? `${key.namePrefix ?? ""}<new>`;
    if (s.name && key.namePrefix && !s.name.startsWith(key.namePrefix)) {
      return { ok: false, reason: "name_scope", detail: `key ${key.id} only enrolls names starting ${key.namePrefix}` };
    }
    return {
      ok: true,
      principal: { agentId: `explain:${name}`, gid: key.gid, groups: key.groups },
      name,
      guest: key.guest,
      notes: [`a new agent enrolled with key ${key.id}`],
    };
  }
  if ("control" in s) {
    const p = s.control;
    const as = p.as ?? (p.kind === "launch" || p.kind === "hosted" ? "agent" : "person");
    const readerKind = p.kind === "read" ? (p.readerKind ?? "browser") : undefined;
    const client = p.kind === "hosted" ? (p.client ?? "mcp") : undefined;
    const identity = { kind: p.kind, userId: p.userId, orgId: p.orgId, email: p.email, role: p.role, workspaceId: p.workspaceId, scopes: [], readerKind, client };
    const rule = matchControlRule(identity, policy, as);
    const who = as === "agent" ? `an agent ${p.userId} enrols (${p.kind}${client ? ` ${client}` : ""} credential)` : `relay-control user ${p.userId} (${p.kind}${readerKind ? `, ${readerKind}` : ""})`;
    if (!rule) return { ok: false, reason: "no_control_rule", detail: `no controlPrincipals rule matches ${who}` };
    const index = policy.controlPrincipals.indexOf(rule);
    const name = as === "agent" ? `<agent of ${p.userId}>` : `ctl:${p.userId}`;
    // A person who already uploaded owns their sessions as the stored ctl: agent, as a real request would.
    const stored = as === "person" ? store?.agentByName(name) : undefined;
    const agentId = stored && stored.keyId === "control" ? stored.id : `explain:${name}`;
    return { ok: true, principal: { agentId, gid: rule.gid, groups: rule.groups }, name, guest: false, notes: [`${who}, by controlPrincipals rule ${index}`] };
  }
  const unknown = [s.gid, ...s.groups].find((g) => !policy.groups.some((x) => x.gid === g));
  if (unknown !== undefined) return { ok: false, reason: "unknown_gid", detail: `the policy defines no gid ${unknown}` };
  const name = s.name ?? `<gid ${s.gid}>`;
  return { ok: true, principal: { agentId: `explain:${name}`, gid: s.gid, groups: s.groups }, name, guest: s.guest, notes: ["a hypothetical agent"] };
}

export function explain(policy: Policy, store: Pick<Store, "agentByName" | "stream"> & Partial<Pick<Store, "session">> | undefined, query: Query, now = Date.now()): Explanation {
  const q = QuerySchema.parse(query);
  const op = q.op as Op;
  const id = q.resource.id;
  const verb = op === "r" ? "read" : "write";
  const subject = resolveSubject(q.as, policy, store, now);
  if (!subject.ok) {
    return {
      decision: "deny",
      reason: subject.reason,
      classified: false,
      subject: { name: "", gid: -1, groups: [], group_names: [], guest: false },
      resource: null,
      steps: [{ step: "subject", detail: subject.detail }],
      summary: `denied: ${subject.detail}`,
    };
  }
  const { principal, name, guest } = subject;
  const card = {
    name,
    gid: principal.gid,
    groups: [...principal.groups],
    group_names: allGroups(principal).map((g) => groupName(policy, g)),
    guest,
  };
  const steps: Explanation["steps"] = subject.notes.map((detail) => ({ step: "subject" as const, detail: `${detail}, in ${card.group_names.join(", ")}${guest ? " (guest)" : ""}` }));

  let stream: (ResolvedStream | ResolvedResource) & { classify?: boolean };
  if (q.resource.kind === "session") {
    const row = store?.session?.(id) ?? (q.resource.gid === undefined ? undefined : { owner: "explain:<first uploader>", gid: q.resource.gid });
    if (!row) {
      steps.push({ step: "resource", detail: `session ${id} isn't recorded; give its first uploader's gid to explain a hypothetical one` });
      return { decision: "deny", reason: "unknown_session", classified: false, subject: card, resource: null, steps, summary: `${name} may not ${verb} session ${id}: unknown session` };
    }
    stream = resolveSession(id, row, policy);
  } else {
    const found = resolveStream(id, store, policy);
    if (!found) {
      steps.push({ step: "resource", detail: `${id} matches no override, registered stream, prefix default or registered agent's inbox` });
      return { decision: "deny", reason: "unknown_stream", classified: false, subject: card, resource: null, steps, summary: `${name} may not ${verb} ${id}: unknown stream` };
    }
    stream = found;
  }
  const acl = (stream.acl ?? []).map((e) => `${e.gid}:${e.perm}`).join(",");
  steps.push({
    step: "resource",
    detail: `${id} from ${stream.source}: gid ${stream.gid} (${groupName(policy, stream.gid)}), mode ${stream.mode}${acl ? `, acl ${acl}` : ""}${stream.classify ? ", classify on" : ""}`,
  });

  const result = check(principal, stream, op, policy.ceilings);
  steps.push(...result.steps);
  const reason = `${result.reason}:${stream.source}`;
  if (!result.allowed) {
    const why = result.steps.at(-1)?.step === "ceiling" ? "refused by a ceiling" : `the ${verb} bit isn't set`;
    return { decision: "deny", reason, classified: false, subject: card, resource: stream, steps, summary: `${name} may not ${verb} ${id}: ${why}` };
  }
  const crosses = !inGroup(principal, stream.gid);
  const classified = op === "w" && (crosses || stream.classify === true);
  steps.push({
    step: "classifier",
    detail: classified
      ? `runs: ${crosses ? "the write crosses a group boundary" : "the stream has classify on"}; it can still deny on content`
      : op === "w" ? "skipped: same-group write without classify" : "skipped: reads are not classified",
  });
  return {
    decision: "allow",
    reason,
    classified,
    subject: card,
    resource: stream,
    steps,
    summary: `${name} may ${verb} ${id}${classified ? ", subject to the classifier" : ""}`,
  };
}

export interface CaseResult {
  case: z.infer<typeof CaseSchema>;
  pass: boolean;
  got: Explanation;
}

/** Runs a list of expected decisions against a policy, for testing a drafted policy before it is applied. */
export function runCases(policy: Policy, store: Pick<Store, "agentByName" | "stream"> & Partial<Pick<Store, "session">> | undefined, cases: Case[], now = Date.now()): CaseResult[] {
  return cases.map((raw) => {
    const c = CaseSchema.parse(raw);
    const got = explain(policy, store, c, now);
    const pass = got.decision === c.expect && (c.classified === undefined || c.classified === got.classified);
    return { case: c, pass, got };
  });
}
