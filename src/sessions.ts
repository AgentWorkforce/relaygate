import type { Context, Hono } from "hono";
import { decideResource, type Deps, type Env, type ResolvedResource } from "./app.js";
import { check, type AclEntry, type Op } from "./mode.js";
import type { Policy } from "./policy.js";
import { deny } from "./relaycast.js";
import type { Agent } from "./store.js";

/**
 * The Sessions proxy (docs/contract.md, "Session uploads" and "Reads and lists"), mounted at /sessions, so a client's
 * Sessions base URL becomes https://<relaygate>/sessions and the paths stay the same.
 *
 * A session is owned by its first uploader and takes that uploader's primary group. Its mode and ACL come from the
 * policy's session defaults for that group, then any per-session override (how a customer shares one session with
 * a guest). Sessions that never came through relaygate have no owner here and are invisible.
 */

export interface SessionsConfig {
  url: string;
  /** rth_st_ service token with rth:sync and rth:read. */
  token: string;
  fetch?: typeof fetch;
}

const SESSION_ID = /^[A-Za-z0-9._:@-]{1,256}$/;
const READ_VIEWS = ["events", "turns", "metadata", "thread", "catalog", "timing", "analysis", "brief"] as const;

/** A session's effective owner, group, mode and ACL. */
export function resolveSession(id: string, row: { owner: string; gid: number }, policy: Policy): ResolvedResource {
  const def = policy.sessionDefaults.find((d) => d.gid === row.gid);
  const override = policy.sessionOverrides.find((o) => o.id === id);
  const acl: AclEntry[] = [...(def?.acl ?? []), ...(override?.acl ?? [])];
  return {
    kind: "session",
    id,
    owner: row.owner,
    gid: override?.gid ?? row.gid,
    mode: override?.mode ?? def?.mode ?? "600",
    acl,
    source: override ? "session-override" : def ? "session-default" : "session-600",
  };
}

export function mountSessions(app: Hono<Env>, deps: Deps, cfg: SessionsConfig): void {
  const doFetch = cfg.fetch ?? fetch;
  const base = cfg.url.endsWith("/") ? cfg.url : `${cfg.url}/`;
  const { store } = deps;
  type Ctx = Context<Env>;

  const audit = (c: Ctx, action: string, op: Op, id: string | null, decision: "allow" | "deny" | "unavailable", stage: "mode" | "classifier" | null, reason: string) =>
    store.audit({ agentId: c.get("agent").id, action, op, resourceKind: "session", resourceId: id, decision, stage, reason });

  const upstream = async (c: Ctx, method: string, path: string, body?: unknown) => {
    try {
      const res = await doFetch(new URL(path.replace(/^\//, ""), base), {
        method,
        headers: { authorization: `Bearer ${cfg.token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await res.text();
      return { status: res.status, body: text ? (JSON.parse(text) as unknown) : null };
    } catch (error) {
      console.error(JSON.stringify({ msg: "sessions upstream error", error: (error as Error).name }));
      return { status: 502, body: { ok: false, error: { code: "relaygate_upstream_unavailable" } } };
    }
  };
  const pass = (c: Ctx, r: { status: number; body: unknown }) => c.json(r.body as object, r.status as 200);
  const upstreamPath = (c: Ctx) => {
    const u = new URL(c.req.url);
    return `${u.pathname.replace(/^\/sessions/, "")}${u.search}`;
  };

  const canRead = (c: Ctx, id: string): boolean => {
    const row = store.session(id);
    if (!row) return false;
    const policy = deps.policy();
    return check(c.get("principal"), resolveSession(id, row, policy), "r", policy.ceilings).allowed;
  };

  /** The write decision for one session; a new session is decided as if the caller owned it (it will). */
  const decideWrite = (c: Ctx, id: string, content: string, row = store.session(id)) => {
    const agent: Agent = c.get("agent");
    const principal = c.get("principal");
    const target = row ?? { owner: agent.id, gid: principal.gid };
    return decideResource(deps, agent, principal, "w", resolveSession(id, target, deps.policy()), content);
  };

  const refusal = (c: Ctx, id: string, d: Awaited<ReturnType<typeof decideWrite>>): Response | undefined => {
    switch (d.status) {
      case "allow":
        audit(c, "session.write", "w", id, "allow", d.stage, d.reason);
        return undefined;
      case "deny":
        audit(c, "session.write", "w", id, "deny", d.stage, d.reason);
        return deny(c, 403, d.error, { op: "w", resource: `session:${id}` });
      case "unavailable":
        audit(c, "session.write", "w", id, "unavailable", d.stage, d.reason);
        return deny(c, 503, "relaygate_unavailable");
      case "invalid":
        return deny(c, 400, "relaygate_bad_request", { detail: d.reason });
    }
  };

  /**
   * Decides every session a request writes, and only when all are allowed claims the new ones, so a refused request
   * never makes anyone an owner. A lost race to another first uploader is decided again against the real owner.
   */
  const gateWrites = async (c: Ctx, writes: Map<string, string>): Promise<Response | undefined> => {
    const fresh: Array<[string, string]> = [];
    for (const [id, content] of writes) {
      const isNew = !store.session(id);
      const refused = refusal(c, id, await decideWrite(c, id, content));
      if (refused) return refused;
      if (isNew) fresh.push([id, content]);
    }
    const agent = c.get("agent");
    for (const [id, content] of fresh) {
      const claimed = store.claimSession(id, agent.id, c.get("principal").gid);
      if (claimed.owner !== agent.id) {
        const refused = refusal(c, id, await decideWrite(c, id, content, claimed));
        if (refused) return refused;
      }
    }
    return undefined;
  };

  const gateRead = (c: Ctx, id: string) => {
    const ok = SESSION_ID.test(id) && canRead(c, id);
    audit(c, "session.read", "r", id, ok ? "allow" : "deny", "mode", ok ? "read" : "read_denied");
    return ok ? undefined : deny(c, 403, "relaygate_denied", { op: "r", resource: `session:${id}` });
  };

  // Append turns. Turns are attributed to the agent, whatever the client sent.
  app.post("/sessions/v1/sessions/:id/turns", async (c) => {
    const id = c.req.param("id");
    if (!SESSION_ID.test(id)) return deny(c, 400, "relaygate_bad_request", { detail: "invalid session id" });
    const body = (await c.req.json().catch(() => null)) as { turns?: unknown } | null;
    if (!body || !Array.isArray(body.turns)) return deny(c, 400, "relaygate_bad_request", { detail: "turns[] required" });
    const name = c.get("agent").name;
    const turns: Array<Record<string, unknown>> = (body.turns as Array<Record<string, unknown>>).map((t) => ({ ...t, sessionOwner: name }));
    const content = turns.map((t) => (typeof t.content === "string" ? t.content : JSON.stringify(t.content ?? ""))).join("\n");
    const refused = await gateWrites(c, new Map([[id, content]]));
    if (refused) return refused;
    return pass(c, await upstream(c, "POST", `/v1/sessions/${encodeURIComponent(id)}/turns`, { ...body, sessionOwner: name, turns }));
  });

  // Batch upload. Every session a batch touches must be writable, or nothing is forwarded.
  app.post("/sessions/v1/ingest", async (c) => {
    const body = (await c.req.json().catch(() => null)) as { records?: unknown } | null;
    if (!body || !Array.isArray(body.records)) return deny(c, 400, "relaygate_bad_request", { detail: "records[] required" });
    const records = body.records as Array<Record<string, unknown>>;
    const bySession = new Map<string, string[]>();
    for (const r of records) {
      const id = r.sessionId;
      if (typeof id !== "string" || !SESSION_ID.test(id)) return deny(c, 400, "relaygate_bad_request", { detail: "every record needs a valid sessionId" });
      const parts = bySession.get(id) ?? [];
      if (typeof r.content === "string") parts.push(r.content);
      bySession.set(id, parts);
    }
    const refused = await gateWrites(c, new Map([...bySession].map(([id, parts]) => [id, parts.join("\n")])));
    if (refused) return refused;
    return pass(c, await upstream(c, "POST", "/v1/ingest", body));
  });

  // List and search: only sessions the caller may read. Filtering after the fact means a page can come back short.
  app.get("/sessions/v1/sessions", async (c) => {
    const res = await upstream(c, "GET", upstreamPath(c));
    if (res.status !== 200 || !res.body || typeof res.body !== "object") return pass(c, res);
    const page = res.body as { sessions?: Array<Record<string, unknown>> };
    const sessions = (page.sessions ?? []).filter((s) => typeof s.sessionId === "string" && canRead(c, s.sessionId));
    audit(c, "session.list", "r", null, "allow", "mode", `filtered:${sessions.length}`);
    return c.json({ ...page, sessions }, 200);
  });

  for (const view of READ_VIEWS) {
    app.get(`/sessions/v1/sessions/:id/${view}`, async (c) => gateRead(c, c.req.param("id")) ?? pass(c, await upstream(c, "GET", upstreamPath(c))));
  }

  app.get("/sessions/v1/events", async (c) => {
    const ids = c.req.queries("session") ?? [];
    if (ids.length !== 1) return deny(c, 400, "relaygate_bad_request", { detail: "exactly one session= is required through relaygate" });
    const id = ids[0]!;
    return gateRead(c, id) ?? pass(c, await upstream(c, "GET", upstreamPath(c)));
  });

  app.all("/sessions/*", (c) => deny(c, 404, "relaygate_route_not_proxied", { path: c.req.path }));
}
