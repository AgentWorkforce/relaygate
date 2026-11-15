import { Hono, type Context } from "hono";
import { z } from "zod";
import { ClassifierUnavailable, type Classifier } from "./classifier.js";
import { inGroup, modeAllows, type Guarded, type Op, type Principal } from "./mode.js";
import type { Policy } from "./policy.js";
import { sameHash, sha256, type Agent, type Store } from "./store.js";

export interface Deps {
  store: Store;
  /** Returns the current operator policy (reloaded by the caller when it changes). */
  policy: () => Policy;
  classifier: () => Classifier;
}

type Env = { Variables: { agent: Agent; principal: Principal } };

const NAME = /^[A-Za-z0-9._:-]{1,128}$/;
const STREAM_ID = /^[\x21-\x7e]{1,512}$/;

const RegisterBody = z.object({ name: z.string().regex(NAME), recovery: z.string().min(16).max(512).optional() });
const StreamBody = z.object({
  gid: z.number().int().nonnegative().optional(),
  mode: z.string().regex(/^[0246]{3}$/),
  classify: z.boolean().default(false),
});
const Resource = z.object({ kind: z.literal("stream"), id: z.string().regex(STREAM_ID) });
const CheckBody = z.object({ op: z.enum(["r", "w"]), resource: Resource, content: z.string().max(200_000).optional() });

function bearer(c: Context): string | undefined {
  const h = c.req.header("authorization");
  return h?.startsWith("Bearer ") ? h.slice(7).trim() : undefined;
}

function deny(c: Context, status: 400 | 401 | 403 | 404 | 409 | 503, error: string, extra: Record<string, unknown> = {}) {
  return c.json({ error, ...extra }, status);
}

export function principalFor(agent: Agent, policy: Policy): Principal {
  const key = policy.enrollmentKeys.find((k) => k.id === agent.keyId);
  return { agentId: agent.id, gid: agent.gid, groups: key?.groups ?? [] };
}

export interface ResolvedStream extends Guarded {
  id: string;
  classify: boolean;
  source: "override" | "registered" | "prefix";
}

/** Operator override, then the registered stream, then the longest matching prefix default. */
export function resolveStream(id: string, store: Store, policy: Policy): ResolvedStream | undefined {
  const override = policy.streamOverrides.find((o) => o.id === id);
  if (override) return { id, owner: null, gid: override.gid, mode: override.mode, classify: override.classify, source: "override" };
  const row = store.stream(id);
  if (row) return { id, owner: row.owner, gid: row.gid, mode: row.mode, classify: row.classify, source: "registered" };
  const prefix = longestPrefix(id, policy);
  if (prefix) return { id, owner: null, gid: prefix.gid, mode: prefix.mode, classify: prefix.classify, source: "prefix" };
  return undefined;
}

function longestPrefix(id: string, policy: Policy) {
  return policy.streamDefaults
    .filter((d) => id.startsWith(d.prefix))
    .sort((a, b) => b.prefix.length - a.prefix.length)[0];
}

const groupName = (policy: Policy, gid: number) => policy.groups.find((g) => g.gid === gid)?.name ?? String(gid);

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
  const policy = deps.policy();
  const stream = resolveStream(streamId, deps.store, policy);
  if (!stream) return { status: "deny", stage: "mode", error: "relaygate_denied", reason: "unknown_stream" };
  if (!modeAllows(principal, stream, op)) {
    return { status: "deny", stage: "mode", error: "relaygate_denied", reason: `mode:${stream.mode}:${stream.source}` };
  }
  const crossesGroup = !inGroup(principal, stream.gid);
  if (op === "w" && (crossesGroup || stream.classify)) {
    if (content === undefined) return { status: "invalid", reason: "content is required for this write" };
    try {
      const verdict = await deps.classifier().classify({
        from: {
          agentId: agent.id,
          name: agent.name,
          groups: [principal.gid, ...principal.groups].map((g) => groupName(policy, g)),
        },
        op: "w",
        resource: { kind: "stream", id: stream.id, group: groupName(policy, stream.gid) },
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
  return { status: "allow", stage: "mode", reason: `mode:${stream.mode}:${stream.source}` };
}

export function createApp(deps: Deps) {
  const app = new Hono<Env>();
  const { store } = deps;

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
    const enrollment = key ? policy.enrollmentKeys.find((k) => !k.revoked && sameHash(k.sha256, sha256(key))) : undefined;
    if (!enrollment) {
      store.audit({ agentId: null, action: "register", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason: "bad_enrollment_key" });
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
      const recovered =
        existing.gid === enrollment.gid &&
        recovery !== undefined &&
        existing.recoveryHash !== null &&
        sameHash(existing.recoveryHash, sha256(recovery));
      if (!recovered) {
        store.audit({ agentId: existing.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "deny", stage: "registration", reason: "name_taken" });
        return deny(c, 409, "relaygate_name_taken");
      }
      store.revokeTokens(existing.id);
      const token = store.issueToken(existing.id);
      store.audit({ agentId: existing.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: "recovered" });
      return c.json({ agent_id: existing.id, gid: existing.gid, token });
    }

    const agent = store.createAgent(name, enrollment.gid, enrollment.id, recovery);
    const token = store.issueToken(agent.id);
    store.audit({ agentId: agent.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: `key:${enrollment.id}` });
    return c.json({ agent_id: agent.id, gid: agent.gid, token });
  });

  // Everything below needs an rg_ token.
  app.use("/v1/*", async (c, next) => {
    const token = bearer(c);
    const agent = token?.startsWith("rg_") ? store.agentForToken(token) : undefined;
    if (!agent) return deny(c, 401, "relaygate_unauthenticated");
    c.set("agent", agent);
    c.set("principal", principalFor(agent, deps.policy()));
    await next();
  });

  app.get("/v1/whoami", (c) => {
    const policy = deps.policy();
    const p = c.get("principal");
    return c.json({
      agent_id: p.agentId,
      name: c.get("agent").name,
      gid: p.gid,
      groups: p.groups,
      group_names: [p.gid, ...p.groups].map((g) => groupName(policy, g)),
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

    store.putStream({ id, owner: agent.id, gid, mode: parsed.data.mode, classify: parsed.data.classify });
    store.audit({ agentId: agent.id, action: "stream.register", op: "w", resourceKind: "stream", resourceId: id, decision: "allow", stage: "registration", reason: `mode:${parsed.data.mode}` });
    return c.json({ id, owner: agent.id, gid, mode: parsed.data.mode, classify: parsed.data.classify });
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

  return app;
}
