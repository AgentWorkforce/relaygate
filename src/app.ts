import { Hono, type Context } from "hono";
import { z } from "zod";
import { ClassifierUnavailable, type Classifier } from "./classifier.js";
import { allGroups, check, inGroup, type AclEntry, type Guarded, type Op, type Principal } from "./mode.js";
import { deny as proxyDeny, mountRelaycast, type RelaycastUpstream } from "./relaycast.js";
import { mountNodeToken } from "./realtime.js";
import { adoptSessions, mountSessions, sessionsCors, type SessionsConfig } from "./sessions.js";
import { ControlUnavailable, controlPrincipal, controlTokenKind, matchControlRule, type ControlAuth } from "./control.js";
import { explain, runCases, CaseSchema, QuerySchema } from "./explain.js";
import { keyUsable, parsePolicy, policyVersion, type EnrollmentKey, type Policy } from "./policy.js";
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
  /** relay-control, for principals that hold only Control credentials; unset means only rg_ principals. */
  control?: ControlAuth;
  /** Called after tokens are revoked, so open sockets close at once rather than at the next revalidation. */
  onTokensRevoked?: () => void;
}

export type Env = { Variables: { agent: Agent; principal: Principal; tokenHash: string; viaControl: boolean } };

const NAME = /^[A-Za-z0-9._:-]{1,128}$/;
const STREAM_ID = /^[\x21-\x7e]{1,512}$/;

const RegisterBody = z.object({
  // `ctl:` names belong to relay-control users (docs/contract.md, "Control principals"); no enrollment key gets them.
  name: z.string().regex(NAME).refine((n) => !n.toLowerCase().startsWith("ctl:"), "names starting ctl: are reserved"),
  recovery: z.string().min(16).max(512).optional(),
});
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
  return { agentId: agent.id, gid: agent.gid, groups: key?.groups ?? agent.groups ?? [] };
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

/** Every decision carries the version of the policy it was evaluated under, for the audit row. */
export type Decision = (
  | { status: "allow"; stage: "mode" | "classifier"; reason: string }
  | { status: "deny"; stage: "mode" | "classifier"; error: "relaygate_denied" | "relaygate_classified"; reason: string }
  | { status: "unavailable"; stage: "classifier"; reason: string }
  | { status: "invalid"; reason: string }
) & { policyVersion?: string };

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
  if (!stream) return { status: "deny", stage: "mode", error: "relaygate_denied", reason: "unknown_stream", policyVersion: policyVersion(policy) };
  return decideResource(deps, agent, principal, op, { kind: "stream", ...stream }, content, policy);
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
  snapshot?: Policy,
): Promise<Decision> {
  const policy = snapshot ?? deps.policy();
  const d = await decideWith(deps, agent, principal, op, x, content, policy);
  return { ...d, policyVersion: policyVersion(policy) };
}

async function decideWith(
  deps: Deps,
  agent: Agent,
  principal: Principal,
  op: Op,
  x: ResolvedResource,
  content: string | undefined,
  policy: Policy,
): Promise<Decision> {
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
  store.policyVersion = () => {
    try {
      return policyVersion(deps.policy());
    } catch {
      return null;
    }
  };

  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/readyz", (c) => {
    try {
      deps.policy();
      return store.ping() ? c.json({ ok: true, policy_version: policyVersion(deps.policy()) }) : c.json({ ok: false }, 503);
    } catch {
      return c.json({ ok: false }, 503);
    }
  });

  // An agent exists in Relaycast from the moment it registers, so others can DM it and see it before it makes a
  // call of its own. Best effort: a failure here is retried lazily on the agent's first proxied request.
  const enrollUpstream = async (agent: Agent) => {
    if (!deps.relaycast) return;
    try {
      await deps.relaycast.agentToken(agent);
    } catch (error) {
      console.error(JSON.stringify({ msg: "upstream registration deferred", agent: agent.name, error: (error as Error).message }));
    }
  };

  /** Longest a device-enrolled agent's token lives before the desktop must register again (docs/contract.md). */
  const DEVICE_TOKEN_MAX_MS = 24 * 3600 * 1000;

  /** Names the policy reserves for someone else (a control plane's server-side identities). */
  const reservedName = (name: string, policy: Policy) => policy.reservedNamePrefixes.some((p) => name.startsWith(p));

  /**
   * POST /v1/register with a relay-control credential, identified by relay-control and grouped by
   * controlPrincipals: a person's device token (their desktop's agents), or a one-time launch credential (one agent a
   * person launched, whose name the credential fixes).
   */
  const registerWithDevice = async (c: Context<Env>, deviceToken: string) => {
    const control = deps.control!;
    const policy = deps.policy();
    let identity;
    try {
      identity = await control.identify(deviceToken);
    } catch (error) {
      if (error instanceof ControlUnavailable) return deny(c, 503, "relaygate_unavailable");
      throw error;
    }
    const refuse = (status: 401 | 403 | 409, error: string, reason: string, extra: Record<string, unknown> = {}) => {
      store.audit({ agentId: null, action: "register", op: null, resourceKind: "agent", resourceId: identity ? `ctl:${identity.userId}` : null, decision: "deny", stage: "registration", reason });
      return deny(c, status, error, extra);
    };
    if (!identity) return refuse(401, "relaygate_unauthenticated", "control_credential_invalid");
    const launch = identity.kind === "launch";
    const needed = launch ? "relay:agent:enrol" : "cli:auth";
    if (!identity.scopes.includes(needed)) return refuse(403, "relaygate_denied", `control_credential_no_${needed}`, { detail: `the credential needs ${needed}` });
    const rule = matchControlRule(identity, policy);
    if (!rule) return refuse(403, "relaygate_denied", "no_control_rule", { detail: "no controlPrincipals rule matches this person" });
    const parsed = RegisterBody.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return deny(c, 400, "relaygate_bad_request", { detail: parsed.error.issues[0]?.message });
    const { name, recovery } = parsed.data;
    if (rule.namePrefix && !name.startsWith(rule.namePrefix)) return refuse(403, "relaygate_name_scope", "name_scope");
    if (reservedName(name, policy)) return refuse(403, "relaygate_name_scope", "name_reserved");
    // A launch credential enrols exactly the agent it names.
    if (launch && name !== identity.agentName) return refuse(403, "relaygate_name_scope", "launch_name_mismatch", { detail: "name must equal the launch credential's agent_name" });
    const keyId = `${launch ? "launch" : "device"}:${identity.userId}`;
    // A desktop agent's token never outlives the device token behind it; a launched agent's is a flat 24 h (it renews
    // with /v1/token/refresh: the single-use launch credential's own short expiry doesn't apply to the agent).
    const expiresAt = launch ? now() + DEVICE_TOKEN_MAX_MS : Math.min(now() + DEVICE_TOKEN_MAX_MS, identity.expiresAt ?? Infinity);
    const answer = (agentId: string, gid: number, token: string) =>
      c.json({ agent_id: agentId, gid, token, expires_at: new Date(expiresAt).toISOString(), user_id: identity!.userId });

    const existing = store.agentByName(name);
    if (existing) {
      // Only the same person gets an existing name back: with the recovery proof, or (a relaunch) with a fresh
      // single-use launch credential naming that very agent.
      const recovered =
        existing.keyId === keyId &&
        (launch || (recovery !== undefined && existing.recoveryHash !== null && sameHash(existing.recoveryHash, sha256(recovery))));
      if (!recovered) return refuse(409, "relaygate_name_taken", "name_taken");
      store.revokeTokens(existing.id);
      deps.onTokensRevoked?.();
      // The person's current rule decides the group (their role or the policy may have changed).
      store.setAgentGroups(existing.id, rule.gid, rule.groups);
      const token = store.issueToken(existing.id, expiresAt);
      store.audit({ agentId: existing.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: `device_recovered:${identity.userId}` });
      await enrollUpstream({ ...existing, gid: rule.gid, groups: rule.groups });
      return answer(existing.id, rule.gid, token);
    }
    const agent = store.createAgent(name, rule.gid, keyId, recovery, false, rule.groups);
    const token = store.issueToken(agent.id, expiresAt);
    store.audit({ agentId: agent.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: `device:${identity.userId}` });
    await enrollUpstream(agent);
    return answer(agent.id, rule.gid, token);
  };

  app.post("/v1/register", async (c) => {
    const key = bearer(c);
    const credentialKind = key && deps.control ? controlTokenKind(key) : undefined;
    if (credentialKind === "device" || credentialKind === "launch") return registerWithDevice(c, key!);
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
    if ((enrollment.namePrefix && !name.startsWith(enrollment.namePrefix)) || reservedName(name, policy)) {
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
        // A desktop-enrolled or launched agent belongs to its person: only their relay-control credential recovers it.
        !existing.keyId.startsWith("device:") &&
        !existing.keyId.startsWith("launch:") &&
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
      await enrollUpstream(existing);
      return c.json({ agent_id: existing.id, gid: existing.gid, token });
    }

    const agent = store.createAgent(name, enrollment.gid, enrollment.id, recovery, enrollment.guest);
    const token = store.issueToken(agent.id);
    store.audit({ agentId: agent.id, action: "register", op: null, resourceKind: "agent", resourceId: name, decision: "allow", stage: "registration", reason: `key:${enrollment.id}` });
    await enrollUpstream(agent);
    return c.json({ agent_id: agent.id, gid: agent.gid, token });
  });

  // Operator endpoints, authorized with the admin token (never an rg_ token).
  const ExplainBody = z.union([
    QuerySchema.extend({ policy: z.unknown().optional() }),
    z.object({ policy: z.unknown().optional(), cases: z.array(CaseSchema).min(1).max(1000) }),
  ]);
  const adminRefusal = (c: Context) => {
    const token = bearer(c);
    if (!deps.adminToken) return deny(c, 404, "relaygate_not_found");
    if (!token || !sameHash(sha256(token), sha256(deps.adminToken))) return deny(c, 401, "relaygate_unauthenticated");
    return undefined;
  };

  // The audit log, for operators and acceptance evidence. Rows never contain message content.
  app.get("/admin/v1/audit", (c) => {
    const refused = adminRefusal(c);
    if (refused) return refused;
    const after = Number(c.req.query("after") ?? 0);
    const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 200), 1), 1000);
    if (!Number.isInteger(after) || after < 0 || !Number.isInteger(limit)) return deny(c, 400, "relaygate_bad_request");
    const rows = store.auditSince(after, limit, c.req.query("agent") || undefined);
    return c.json({ policy_version: policyVersion(deps.policy()), rows });
  });

  // Gives sessions uploaded before relaygate an owner, by their uploader (docs/contract.md, "Adopting existing sessions").
  const AdoptBody = z.object({
    readToken: z.string().min(8),
    orgId: z.string().min(1),
    workspaceId: z.string().min(1),
    /** Continue a run that stopped at maxPages (its report's nextCursor). */
    cursor: z.string().min(1).optional(),
    maxPages: z.number().int().positive().max(5000).optional(),
  });
  app.post("/admin/v1/sessions/adopt", async (c) => {
    const refused = adminRefusal(c);
    if (refused) return refused;
    if (!deps.sessions) return deny(c, 404, "relaygate_not_found");
    const parsed = AdoptBody.safeParse(await c.req.json().catch(() => null));
    if (!parsed.success) return deny(c, 400, "relaygate_bad_request", { detail: parsed.error.issues[0]?.message });
    const dryRun = c.req.query("dryRun") === "1" || c.req.query("dryRun") === "true";
    return c.json(await adoptSessions(deps, deps.sessions, { ...parsed.data, dryRun }));
  });

  app.post("/admin/v1/explain", async (c) => {
    const refused = adminRefusal(c);
    if (refused) return refused;
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
  /** A caller holding only a relay-control credential (Sessions routes only): identified, then mapped by policy. */
  const authenticateControl = async (c: Context<Env>, token: string, checkOnly = false): Promise<Response | undefined> => {
    const control = deps.control!;
    let identity;
    try {
      identity = await control.identify(token);
    } catch (error) {
      if (error instanceof ControlUnavailable) {
        console.error(JSON.stringify({ msg: "control introspection unavailable", error: error.message }));
        return deny(c, 503, "relaygate_unavailable");
      }
      throw error;
    }
    if (!identity) {
      store.audit({ agentId: null, action: "auth", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason: `control_${controlTokenKind(token)}_invalid` });
      return deny(c, 401, "relaygate_unauthenticated");
    }
    const policy = deps.policy();
    const rule = matchControlRule(identity, policy);
    if (!rule) {
      store.audit({ agentId: null, action: "auth", op: null, resourceKind: "agent", resourceId: `ctl:${identity.userId}`, decision: "deny", stage: "auth", reason: "no_control_rule" });
      return deny(c, 403, "relaygate_denied", { detail: "no controlPrincipals rule matches this user" });
    }
    // Uploads need a device token that may sync; a read token (or a device token without rth:sync) only reads.
    const writes = !checkOnly && c.req.method !== "GET" && c.req.method !== "HEAD";
    if (writes && (identity.kind !== "device" || !identity.scopes.includes("rth:sync"))) {
      store.audit({ agentId: null, action: "auth", op: "w", resourceKind: "agent", resourceId: `ctl:${identity.userId}`, decision: "deny", stage: "auth", reason: `control_${identity.kind}_cannot_write` });
      return deny(c, 403, "relaygate_denied", { detail: "uploads need a device token with rth:sync" });
    }
    if (!checkOnly && !writes && !identity.scopes.includes("rth:read")) {
      return deny(c, 403, "relaygate_denied", { detail: "this credential has no rth:read" });
    }
    let resolved;
    try {
      resolved = controlPrincipal(store, identity, rule);
    } catch (error) {
      console.error(JSON.stringify({ msg: "control identity refused", error: (error as Error).message }));
      return deny(c, 403, "relaygate_denied", { detail: "this identity collides with a registered agent" });
    }
    const { agent, principal } = resolved;
    c.set("agent", agent);
    c.set("principal", principal);
    c.set("tokenHash", sha256(token));
    c.set("viaControl", true);
    return undefined;
  };

  const authenticate = async (c: Context<Env>, next: () => Promise<void>) => {
    const onSessions = c.req.path.startsWith("/sessions/");
    // CORS preflights carry no credential, and relay-control's internal mint calls carry the read API's own secret:
    // both are handled by the Sessions proxy itself.
    if (onSessions && (c.req.method === "OPTIONS" || c.req.path.startsWith("/sessions/internal/"))) return next();
    // Token revocation (always safe) and the health check need no principal.
    if (onSessions && (c.req.path === "/sessions/v1/auth/token/revoke" || c.req.path === "/sessions/healthz")) return next();
    const relaygateToken = onSessions ? c.req.header("x-relaygate-token")?.trim() : undefined;
    const presented = bearer(c);
    // /v1/check also answers for a person's device token, e.g. a control plane checking a spawn as the person
    // launching it. Never a launch credential: introspecting it would redeem it before the node can register.
    if (c.req.path === "/v1/check" && deps.control && presented && controlTokenKind(presented) === "device") {
      const refused = await authenticateControl(c, presented, true);
      if (refused) return refused;
      return next();
    }
    if (onSessions && !relaygateToken && deps.control && presented && controlTokenKind(presented)) {
      const refused = await authenticateControl(c, presented);
      if (refused) return refused;
      return next();
    }
    // On Sessions routes the caller's Authorization carries its own Sessions credential and the rg_ token comes in
    // X-Relaygate-Token (docs/contract.md, "Session uploads").
    const token = relaygateToken ?? presented;
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
    c.set("viaControl", false);
    await next();
  };
  app.use("/v1/*", authenticate);
  // Registered before auth, so relaygate's own refusals reach the dashboard with CORS headers too.
  if (deps.sessions?.corsOrigins?.length) app.use("/sessions/*", sessionsCors(deps.sessions));
  app.use("/sessions/*", authenticate);

  // Launched agents can't re-register (their launch credential is single-use): they refresh before expiry instead.
  app.post("/v1/token/refresh", (c) => {
    const agent = c.get("agent");
    if (!agent.keyId.startsWith("launch:")) {
      return deny(c, 403, "relaygate_denied", {
        detail: agent.keyId.startsWith("device:") ? "re-register with your device token" : "this token doesn't expire",
      });
    }
    const expiresAt = now() + DEVICE_TOKEN_MAX_MS;
    store.revokeTokenHash(c.get("tokenHash"));
    deps.onTokensRevoked?.();
    const token = store.issueToken(agent.id, expiresAt);
    store.audit({ agentId: agent.id, action: "token.refresh", op: null, resourceKind: "agent", resourceId: agent.name, decision: "allow", stage: "auth", reason: agent.keyId });
    return c.json({ token, expires_at: new Date(expiresAt).toISOString() });
  });

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
      store.audit({ agentId: agent.id, action: "check", op, resourceKind: resource.kind, resourceId: resource.id, decision, stage, reason, policyVersion: d.policyVersion });

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
