import { Hono, type Context } from "hono";
import { z } from "zod";
import { ClassifierUnavailable, type Classifier } from "./classifier.js";
import { allGroups, check, inGroup, type AclEntry, type Guarded, type Op, type Principal } from "./mode.js";
import { deny as proxyDeny, mountRelaycast, type RelaycastUpstream } from "./relaycast.js";
import { mountNodeToken } from "./realtime.js";
import { mountSessions, type SessionsConfig } from "./sessions.js";
import { explain, runCases, CaseSchema, QuerySchema } from "./explain.js";
import { keyUsable, parsePolicy, type EnrollmentKey, type Policy } from "./policy.js";
import { sameHash, sha256, type Agent, type Store } from "./store.js";

export interface Deps {
  store: Store;
  /** Returns the current operator policy (reloaded by the caller when it changes). */
  policy: () => Policy;
  classifier: () => Classifier;
  /** Clock for key expiry; defaults to Date.now. */
  now?: () => number;
  /** Operator token for /admin/v1/*. Unset disables the admin endpoints. */
  adminToken?: string;
  /** The Relaycast upstream; unset disables the Relaycast proxy. */
  relaycast?: RelaycastUpstream;
  /** The Sessions upstream; unset disables the Sessions proxy. */
  sessions?: SessionsConfig;
  /** Called after tokens are revoked, so open sockets close at once rather than at the next revalidation. */
  onTokensRevoked?: () => void;
}

export type Env = { Variables: { agent: Agent; principal: Principal; tokenHash: string } };

const NAME = /^[A-Za-z0-9._:-]{1,128}$/;
const STREAM_ID = /^[\x21-\x7e]{1,512}$/;

const RegisterBody = z.object({ name: z.string().regex(NAME), recovery: z.string().min(16).max(512).optional() });
const StreamBody = z.object({
  gid: z.number().int().nonnegative().optional(),
  mode: z.string().regex(/^[0246]{3}$/),
  classify: z.boolean().default(false),
  acl: z.array(z.object({ gid: z.number().int().nonnegative(), perm: z.enum(["r", "w", "rw"]) })).max(64).default([]),
});
const Resource = z.object({ kind: z.literal("stream"), id: z.string().regex(STREAM_ID) });
const CheckBody = z.object({ op: z.enum(["r", "w"]), resource: Resource, content: z.string().max(200_000).optional() });

function bearer(c: Context): string | undefined {
  const h = c.req.header("authorization");
  return h?.startsWith("Bearer ") ? h.slice(7).trim() : undefined;
}

export function deny(c: Context, status: 400 | 401 | 403 | 404 | 409 | 503, error: string, extra: Record<string, unknown> = {}) {
  return c.json({ error, ...extra }, status);
}

export function principalFor(agent: Agent, policy: Policy): Principal {
  const key = policy.enrollmentKeys.find((k) => k.id === agent.keyId);
  return { agentId: agent.id, gid: agent.gid, groups: key?.groups ?? [] };
}

/** A guest agent, by the key it enrolled with now or the flag recorded when it registered. */
export function isGuest(agent: Agent, policy: Policy): boolean {
  return agent.guest || policy.enrollmentKeys.some((k) => k.id === agent.keyId && k.guest);
}

/**
 * Why a guest agent's tokens have ended, or undefined while they still work. A guest key that is revoked,
 * expired or gone from the policy ends every token issued from it (docs/contract.md, "Guests").
 */
export function guestEnded(agent: Agent, policy: Policy, now: number): string | undefined {
  if (!isGuest(agent, policy)) return undefined;
  const key = policy.enrollmentKeys.find((k) => k.id === agent.keyId);
  if (!key) return "guest_key_removed";
  if (key.revoked) return "guest_key_revoked";
  if (!keyUsable(key, now)) return "guest_key_expired";
  return undefined;
}

/**
 * Records every agent of a guest key as a guest, then revokes every token issued from guest keys that are revoked,
 * expired or gone from the policy. Returns the revoked hashes.
 */
export function sweepGuestKeys(store: Store, policy: Policy, now: number): string[] {
  for (const k of policy.enrollmentKeys) if (k.guest) store.markKeyGuest(k.id);
  return store.guestKeyIds().flatMap((id) => {
    const key = policy.enrollmentKeys.find((k) => k.id === id);
    return key && keyUsable(key, now) ? [] : store.revokeGuestKeyTokens(id);
  });
}

/** The sender card stamped on everything relaygate forwards and returned by /v1/whoami. */
export function provenance(agent: Agent, principal: Principal, policy: Policy) {
  return {
    agent: agent.name,
    groups: allGroups(principal).map((g) => groupName(policy, g)),
    ...(isGuest(agent, policy) ? { guest: true as const } : {}),
  };
}

export interface ResolvedStream extends Guarded {
  id: string;
  classify: boolean;
  acl: AclEntry[];
  source: "override" | "registered" | "prefix";
}

/** Operator override, then the registered stream, then the longest matching prefix default. */
export function resolveStream(id: string, store: Pick<Store, "stream"> | undefined, policy: Policy): ResolvedStream | undefined {
  const override = policy.streamOverrides.find((o) => o.id === id);
  if (override) return { id, owner: null, gid: override.gid, mode: override.mode, classify: override.classify, acl: override.acl, source: "override" };
  const row = store?.stream(id);
  if (row) return { id, owner: row.owner, gid: row.gid, mode: row.mode, classify: row.classify, acl: row.acl, source: "registered" };
  const prefix = longestPrefix(id, policy);
  if (prefix) return { id, owner: null, gid: prefix.gid, mode: prefix.mode, classify: prefix.classify, acl: prefix.acl, source: "prefix" };
  return undefined;
}

export function longestPrefix(id: string, policy: Policy) {
  return policy.streamDefaults
    .filter((d) => id.startsWith(d.prefix))
    .sort((a, b) => b.prefix.length - a.prefix.length)[0];
}

export const groupName = (policy: Policy, gid: number) => policy.groups.find((g) => g.gid === gid)?.name ?? String(gid);

export type Decision =
  | { status: "allow"; stage: "mode" | "classifier"; reason: string }
  | { status: "deny"; stage: "mode" | "classifier"; error: "relaygate_denied" | "relaygate_classified"; reason: string }
  | { status: "unavailable"; stage: "classifier"; reason: string }
  | { status: "invalid"; reason: string };

/** The whole decision for one request: mode check first, then the classifier when the contract requires it. */
export async function decide(
  deps: Deps,
  agent: Agent,
  principal: Principal,
  op: Op,
  streamId: string,
  content: string | undefined,
): Promise<Decision> {
  const stream = resolveStream(streamId, deps.store, deps.policy());
  if (!stream) return { status: "deny", stage: "mode", error: "relaygate_denied", reason: "unknown_stream" };
  return decideResource(deps, agent, principal, op, { kind: "stream", ...stream }, content);
}

export interface ResolvedResource extends Guarded {
  kind: "stream" | "session";
  id: string;
  /** Streams only: classify every write. */
  classify?: boolean;
  source: string;
}

/** The decision for a resolved resource: mode check first, then the classifier when the contract requires it. */
export async function decideResource(
  deps: Deps,
  agent: Agent,
  principal: Principal,
  op: Op,
  x: ResolvedResource,
  content: string | undefined,
): Promise<Decision> {
  const policy = deps.policy();
  const result = check(principal, x, op, policy.ceilings);
  const modeReason = `${result.reason}:${x.source}`;
  if (!result.allowed) return { status: "deny", stage: "mode", error: "relaygate_denied", reason: modeReason };
  const crossesGroup = !inGroup(principal, x.gid);
  if (op === "w" && (crossesGroup || x.classify === true)) {
    if (content === undefined) return { status: "invalid", reason: "content is required for this write" };
    try {
      const verdict = await deps.classifier().classify({
        from: {
          agentId: agent.id,
          name: agent.name,
          groups: allGroups(principal).map((g) => groupName(policy, g)),
          guest: isGuest(agent, policy),
        },
        op: "w",
        resource: { kind: x.kind, id: x.id, group: groupName(policy, x.gid) },
        content,
      });
      if (verdict.decision === "deny") {
        return { status: "deny", stage: "classifier", error: "relaygate_classified", reason: verdict.reason };
      }
      return { status: "allow", stage: "classifier", reason: verdict.reason };
    } catch (error) {
      if (error instanceof ClassifierUnavailable) return { status: "unavailable", stage: "classifier", reason: error.message };
      throw error;
    }
  }
  return { status: "allow", stage: "mode", reason: modeReason };
}

export function createApp(deps: Deps) {
  const app = new Hono<Env>();
  const { store } = deps;
  const now = deps.now ?? Date.now;

  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/readyz", (c) => {
    try {
      deps.policy();
      return store.ping() ? c.json({ ok: true }) : c.json({ ok: false }, 503);
    } catch {
      return c.json({ ok: false }, 503);
    }
  });

  app.post("/v1/register", async (c) => {
    const key = bearer(c);
    const policy = deps.policy();
    const matches: EnrollmentKey[] = key ? policy.enrollmentKeys.filter((k) => sameHash(k.sha256, sha256(key))) : [];
    const enrollment = matches.find((k) => keyUsable(k, now()));
    const found = matches[0];
    if (!enrollment) {
      const reason = !found ? "bad_enrollment_key" : found.revoked ? `key_revoked:${found.id}` : `key_expired:${found.id}`;
      store.audit({ agentId: null, action: "register", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason });
      return deny(c, 401, "relaygate_unauthenticated");
    }
    const parsed = RegisterBody.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return deny(c, 400, "relaygate_bad_request", { detail: parsed.error.issues[0]?.message });
    const { name, recovery } = parsed.data;
    if (enrollment.namePrefix && !name.startsWith(enrollment.namePrefix)) {
      store.audit({ agentId: null, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "deny", stage: "registration", reason: "name_scope" });
      return deny(c, 403, "relaygate_name_scope");
    }

    const existing = store.agentByName(name);
    if (existing) {
      // Effective guest status, persisted first, so a key that just turned guest can't be escaped by rebinding.
      if (!existing.guest && isGuest(existing, policy)) {
        store.markKeyGuest(existing.keyId);
        existing.guest = true;
      }
      const recovered =
        existing.gid === enrollment.gid &&
        existing.guest === enrollment.guest &&
        recovery !== undefined &&
        existing.recoveryHash !== null &&
        sameHash(existing.recoveryHash, sha256(recovery));
      if (!recovered) {
        store.audit({ agentId: existing.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "deny", stage: "registration", reason: "name_taken" });
        return deny(c, 409, "relaygate_name_taken");
      }
      store.revokeTokens(existing.id);
      deps.onTokensRevoked?.();
      // The key that recovered the agent now governs it (key rotation: the old key may have expired).
      if (existing.keyId !== enrollment.id) store.setAgentKey(existing.id, enrollment.id, enrollment.guest);
      const token = store.issueToken(existing.id);
      store.audit({ agentId: existing.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: "recovered" });
      return c.json({ agent_id: existing.id, gid: existing.gid, token });
    }

    const agent = store.createAgent(name, enrollment.gid, enrollment.id, recovery, enrollment.guest);
    const token = store.issueToken(agent.id);
    store.audit({ agentId: agent.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: `key:${enrollment.id}` });
    return c.json({ agent_id: agent.id, gid: agent.gid, token });
  });

  // Operator endpoints, authorized with the admin token (never an rg_ token).
  const ExplainBody = z.union([
    QuerySchema.extend({ policy: z.unknown().optional() }),
    z.object({ policy: z.unknown().optional(), cases: z.array(CaseSchema).min(1).max(1000) }),
  ]);
  app.post("/admin/v1/explain", async (c) => {
    const token = bearer(c);
    if (!deps.adminToken) return deny(c, 404, "relaygate_not_found");
    if (!token || !sameHash(sha256(token), sha256(deps.adminToken))) return deny(c, 401, "relaygate_unauthenticated");
    const parsed = ExplainBody.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return deny(c, 400, "relaygate_bad_request", { detail: parsed.error.issues[0]?.message });
    let policy: Policy;
    try {
      // A draft policy is checked exactly like a file the operator would load; nothing is applied.
      policy = parsed.data.policy === undefined ? deps.policy() : parsePolicy(parsed.data.policy);
    } catch (error) {
      return deny(c, 400, "relaygate_bad_policy", { detail: (error as Error).message.slice(0, 2000) });
    }
    const draft = parsed.data.policy !== undefined;
    if ("cases" in parsed.data) {
      const results = runCases(policy, store, parsed.data.cases, now());
      const failed = results.filter((r) => !r.pass).length;
      return c.json({ draft, passed: results.length - failed, failed, results });
    }
    return c.json({ draft, ...explain(policy, store, parsed.data, now()) });
  });

  // Everything below needs an rg_ token.
  const authenticate = async (c: Context<Env>, next: () => Promise<void>) => {
    const token = bearer(c);
    const agent = token?.startsWith("rg_") ? store.agentForToken(token) : undefined;
    if (!agent) return deny(c, 401, "relaygate_unauthenticated");
    const policy = deps.policy();
    // A key that became a guest key makes its agents guests for good.
    if (!agent.guest && isGuest(agent, policy)) {
      store.markKeyGuest(agent.keyId);
      agent.guest = true;
    }
    const ended = guestEnded(agent, policy, now());
    if (ended) {
      // Permanent: un-revoking or extending the key later doesn't bring these tokens back.
      store.revokeTokens(agent.id);
      deps.onTokensRevoked?.();
      store.audit({ agentId: agent.id, action: "auth", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason: ended });
      return deny(c, 401, "relaygate_unauthenticated");
    }
    c.set("agent", agent);
    c.set("principal", principalFor(agent, policy));
    c.set("tokenHash", sha256(token!));
    await next();
  };
  app.use("/v1/*", authenticate);
  app.use("/sessions/*", authenticate);

  app.get("/v1/whoami", (c) => {
    const policy = deps.policy();
    const p = c.get("principal");
    const agent = c.get("agent");
    return c.json({
      agent_id: p.agentId,
      name: agent.name,
      gid: p.gid,
      groups: p.groups,
      group_names: allGroups(p).map((g) => groupName(policy, g)),
      guest: isGuest(agent, policy),
      relaygate: provenance(agent, p, policy),
    });
  });

  app.put("/v1/streams/:id", async (c) => {
    const id = c.req.param("id");
    const agent = c.get("agent");
    const principal = c.get("principal");
    const policy = deps.policy();
    if (!STREAM_ID.test(id)) return deny(c, 400, "relaygate_bad_request", { detail: "invalid stream id" });
    const parsed = StreamBody.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return deny(c, 400, "relaygate_bad_request", { detail: parsed.error.issues[0]?.message });
    const gid = parsed.data.gid ?? principal.gid;
    const { mode, classify, acl } = parsed.data;
    const unknownGid = acl.find((e) => !policy.groups.some((g) => g.gid === e.gid));
    if (unknownGid) return deny(c, 400, "relaygate_bad_request", { detail: `acl names unknown gid ${unknownGid.gid}` });

    const refuse = (reason: string) => {
      store.audit({ agentId: agent.id, action: "stream.register", op: "w", resourceKind: "stream", resourceId: id, decision: "deny", stage: "registration", reason });
      return deny(c, 403, "relaygate_denied", { op: "w", resource: id });
    };
    if (policy.streamOverrides.some((o) => o.id === id)) return refuse("operator_override");
    if (!inGroup(principal, gid)) return refuse("gid_not_own_group");
    const prefix = longestPrefix(id, policy);
    if (!prefix || !inGroup(principal, prefix.gid)) return refuse("prefix_not_own_group");
    const existing = store.stream(id);
    if (existing && existing.owner !== agent.id) return refuse("not_owner");

    store.putStream({ id, owner: agent.id, gid, mode, classify, acl });
    const aclText = acl.map((e) => `+acl:${e.gid}:${e.perm}`).join("");
    store.audit({ agentId: agent.id, action: "stream.register", op: "w", resourceKind: "stream", resourceId: id, decision: "allow", stage: "registration", reason: `mode:${mode}${aclText}` });
    return c.json({ id, owner: agent.id, gid, mode, classify, acl });
  });

  app.post("/v1/check", async (c) => {
    const agent = c.get("agent");
    const parsed = CheckBody.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return deny(c, 400, "relaygate_bad_request", { detail: parsed.error.issues[0]?.message });
    const { op, resource, content } = parsed.data;
    const d = await decide(deps, agent, c.get("principal"), op, resource.id, content);
    const audit = (decision: "allow" | "deny" | "unavailable", stage: "mode" | "classifier" | null, reason: string) =>
      store.audit({ agentId: agent.id, action: "check", op, resourceKind: resource.kind, resourceId: resource.id, decision, stage, reason });

    switch (d.status) {
      case "invalid":
        return deny(c, 400, "relaygate_bad_request", { detail: d.reason });
      case "allow":
        audit("allow", d.stage, d.reason);
        return c.json({ decision: "allow" });
      case "deny":
        audit("deny", d.stage, d.reason);
        return deny(c, 403, d.error, { op, resource: resource.id });
      case "unavailable":
        audit("unavailable", d.stage, d.reason);
        return deny(c, 503, "relaygate_unavailable");
    }
  });

  if (deps.relaycast) {
    mountRelaycast(app, deps, deps.relaycast);
    mountNodeToken(app, deps, deps.relaycast);
  }
  if (deps.sessions) mountSessions(app, deps, deps.sessions);
  // Allowlist only: every other /v1 route is refused before anything reaches upstream.
  app.all("/v1/*", (c) => proxyDeny(c, 404, "relaygate_route_not_proxied", { path: c.req.path }));

  return app;
}
