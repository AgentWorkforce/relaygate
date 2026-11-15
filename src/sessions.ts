import { gunzipSync, zstdDecompressSync } from "node:zlib";
import type { Context, Hono } from "hono";
import { decideResource, type Deps, type Env, type ResolvedResource } from "./app.js";
import { check, type AclEntry, type Op } from "./mode.js";
import type { Policy } from "./policy.js";
import { deny } from "./relaycast.js";
import type { Agent } from "./store.js";

/**
 * The Sessions proxy (docs/contract.md, "Session uploads" and "Reads and lists"), mounted at /sessions, so a client's
 * Sessions base URL becomes https://<relaygate>/sessions and the paths stay the same (or served at the root for the
 * hosts in `SessionsConfig.hosts`; see `routeSessionsHosts`).
 *
 * relaygate holds no Sessions credential of its own. The caller authenticates to relaygate with its rg_ token in
 * `X-Relaygate-Token` and sends its own Sessions credential in `Authorization`, which is forwarded unchanged, so
 * Sessions records the real uploader. A caller that sends its rg_ token in `Authorization` instead gets the optional
 * configured service credential upstream, or a 401 when there is none.
 *
 * A session is owned by its first uploader and takes that uploader's primary group. Its mode and ACL come from the
 * policy's session defaults for that group, then any per-session override (how a customer shares one session with
 * a guest). Sessions that never came through relaygate have no owner here and are invisible.
 */

export interface SessionsConfig {
  /** Origin that takes uploads (POST). */
  uploadUrl: string;
  /** Origin that serves reads (GET). Often the same as uploadUrl. */
  readUrl: string;
  /** Optional service credential, used only for callers that send no Sessions credential of their own. */
  token?: string;
  /** Hosts whose requests are Sessions requests at the root path (no /sessions prefix). */
  hosts?: string[];
  fetch?: typeof fetch;
}

/** Request headers forwarded to Sessions besides Authorization. Trust headers (x-relay-ingest-*) never are. */
const PASS_REQUEST = ["content-type", "content-encoding", "accept", "x-agent-relay-capture-policy-revision", "x-correlation-id", "idempotency-key"];
/** Response headers passed back to the caller. */
const PASS_RESPONSE = ["content-type", "retry-after", "x-relay-admission", "x-relayhistory-workspace-id", "x-sessions-read-continuation", "x-correlation-id"];
/** The largest upload body relaygate inspects (wire and decoded); Sessions' own cap is 2 MiB. */
const MAX_UPLOAD = 4 * 1024 * 1024;

/** Serves Sessions paths at the root for the configured hosts, by mapping them under /sessions. */
export function routeSessionsHosts(fetchFn: (req: Request) => Response | Promise<Response>, hosts: string[] = []) {
  const set = new Set(hosts.map((h) => h.toLowerCase()));
  return (req: Request): Response | Promise<Response> => {
    const host = (req.headers.get("host") ?? new URL(req.url).host).toLowerCase().replace(/:\d+$/, "");
    if (!set.has(host)) return fetchFn(req);
    const url = new URL(req.url);
    url.pathname = `/sessions${url.pathname}`;
    return fetchFn(new Request(url, req));
  };
}

const SESSION_ID = /^[A-Za-z0-9._:@-]{1,256}$/;
const READ_VIEWS = ["events", "turns", "metadata", "thread", "catalog", "timing", "analysis", "brief", "summary"] as const;

/** A session's effective owner, group, mode and ACL. */
export function resolveSession(id: string, row: { owner: string; gid: number }, policy: Policy): ResolvedResource {
  const def = policy.sessionDefaults.find((d) => d.gid === row.gid);
  const override = policy.sessionOverrides.find((o) => o.id === id);
  const acl: AclEntry[] = [...(def?.acl ?? []), ...(override?.acl ?? [])];
  return {
    kind: "session",
    id,
    owner: row.owner,
    gid: row.gid,
    mode: override?.mode ?? def?.mode ?? "600",
    acl,
    source: override ? "session-override" : def ? "session-default" : "session-600",
  };
}

export function mountSessions(app: Hono<Env>, deps: Deps, cfg: SessionsConfig): void {
  const doFetch = cfg.fetch ?? fetch;
  const slash = (u: string) => (u.endsWith("/") ? u : `${u}/`);
  const { store } = deps;
  type Ctx = Context<Env>;

  const audit = (c: Ctx, action: string, op: Op, id: string | null, decision: "allow" | "deny" | "unavailable", stage: "mode" | "classifier" | null, reason: string, policyVersion?: string) =>
    store.audit({ policyVersion, agentId: c.get("agent").id, action, op, resourceKind: "session", resourceId: id, decision, stage, reason });

  /** The caller's own Sessions credential, or the configured service one, or none. */
  const credential = (c: Ctx): string | undefined => {
    const auth = c.req.header("authorization");
    if (c.req.header("x-relaygate-token") && auth && !/^Bearer\s+rg_/.test(auth)) return auth;
    return cfg.token ? `Bearer ${cfg.token}` : undefined;
  };

  interface Upstream {
    status: number;
    headers: Headers;
    text: string;
  }

  const upstream = async (c: Ctx, base: string, method: string, path: string, body?: BodyInit): Promise<Upstream | Response> => {
    const auth = credential(c);
    if (!auth) return deny(c, 401, "relaygate_unauthenticated", { detail: "send your Sessions credential in Authorization and your rg_ token in X-Relaygate-Token" });
    const headers: Record<string, string> = { authorization: auth };
    for (const h of PASS_REQUEST) {
      const v = c.req.header(h);
      if (v) headers[h] = v;
    }
    try {
      const res = await doFetch(new URL(path.replace(/^\//, ""), slash(base)), { method, headers, body });
      return { status: res.status, headers: res.headers, text: await res.text() };
    } catch (error) {
      console.error(JSON.stringify({ msg: "sessions upstream error", error: (error as Error).name }));
      return deny(c, 502, "relaygate_upstream_unavailable");
    }
  };

  /** Passes an upstream response back: status, the safe headers, and the body (as is, or replaced). */
  const pass = (r: Upstream | Response, replaced?: unknown): Response => {
    if (r instanceof Response) return r;
    const headers = new Headers();
    for (const h of PASS_RESPONSE) {
      const v = r.headers.get(h);
      if (v) headers.set(h, v);
    }
    if (replaced !== undefined) headers.set("content-type", "application/json");
    return new Response(replaced === undefined ? r.text : JSON.stringify(replaced), { status: r.status, headers });
  };
  const json = (r: Upstream): any => {
    try {
      return r.text ? JSON.parse(r.text) : null;
    } catch {
      return null;
    }
  };
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
        audit(c, "session.write", "w", id, "allow", d.stage, d.reason, d.policyVersion);
        return undefined;
      case "deny":
        audit(c, "session.write", "w", id, "deny", d.stage, d.reason, d.policyVersion);
        return deny(c, 403, d.error, { op: "w", resource: `session:${id}` });
      case "unavailable":
        audit(c, "session.write", "w", id, "unavailable", d.stage, d.reason, d.policyVersion);
        return deny(c, 503, "relaygate_unavailable");
      case "invalid":
        return deny(c, 400, "relaygate_bad_request", { detail: d.reason });
    }
  };

  /**
   * Decides every session a request writes, then claims the new ones in one transaction. If another uploader got
   * one of them first (while the classifier ran), nothing is claimed and the whole request is decided again against
   * the real owners. Returns the ids this request claimed.
   */
  const gateWrites = async (c: Ctx, writes: Map<string, string>, attempt = 0): Promise<Response | string[]> => {
    const fresh: string[] = [];
    for (const [id, content] of writes) {
      const isNew = !store.session(id);
      const refused = refusal(c, id, await decideWrite(c, id, content));
      if (refused) return refused;
      if (isNew) fresh.push(id);
    }
    if (fresh.length === 0) return [];
    const result = store.claimSessions(fresh, c.get("agent").id, c.get("principal").gid);
    if (result.claimed) return fresh;
    if (attempt > 0) return deny(c, 409, "relaygate_conflict", { detail: "sessions were claimed concurrently; retry" });
    return gateWrites(c, writes, attempt + 1);
  };

  /**
   * Forwards an upload. Claims are never released, even when Sessions rejects the upload: releasing could hand a
   * session that a concurrent upload filled to another group. A failed first upload leaves the session with the
   * agent that will retry it (session ids are chosen by the uploader).
   */
  const upload = async (c: Ctx, path: string, body: unknown) => pass(await upstream(c, cfg.uploadUrl, "POST", path, JSON.stringify(body)));

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
    const forwarded = { ...body, sessionOwner: name, turns };
    // The classifier sees everything that is forwarded, not only `content`.
    const gate = await gateWrites(c, new Map([[id, JSON.stringify(forwarded)]]));
    if (gate instanceof Response) return gate;
    return upload(c, `/v1/sessions/${encodeURIComponent(id)}/turns`, forwarded);
  });

  // Batch upload. Every session a batch touches must be writable, or nothing is forwarded.
  app.post("/sessions/v1/ingest", async (c) => {
    const body = (await c.req.json().catch(() => null)) as { records?: unknown } | null;
    if (!body || !Array.isArray(body.records)) return deny(c, 400, "relaygate_bad_request", { detail: "records[] required" });
    const name = c.get("agent").name;
    // Attribution relaygate vouches for: a tag naming the agent (client-sent relaygate: tags are dropped), and the
    // agent as sessionOwner wherever a record names one.
    const records: Array<Record<string, unknown>> = (body.records as Array<Record<string, unknown>>).map((r) => {
      const tags = Array.isArray(r.tags) ? r.tags.filter((t) => typeof t === "string" && !t.startsWith("relaygate:")) : [];
      return { ...r, tags: [...tags, `relaygate:agent:${name}`], ...("sessionOwner" in r ? { sessionOwner: name } : {}) };
    });
    const bySession = new Map<string, Array<Record<string, unknown>>>();
    for (const r of records) {
      const id = r.sessionId;
      if (typeof id !== "string" || !SESSION_ID.test(id)) return deny(c, 400, "relaygate_bad_request", { detail: "every record needs a valid sessionId" });
      bySession.set(id, [...(bySession.get(id) ?? []), r]);
    }
    // Each session's classification covers its records and every top-level field the batch forwards.
    const { records: _records, ...envelope } = body as Record<string, unknown>;
    const gate = await gateWrites(c, new Map([...bySession].map(([id, rs]) => [id, JSON.stringify({ ...envelope, records: rs })])));
    if (gate instanceof Response) return gate;
    return upload(c, "/v1/ingest", { ...envelope, records });
  });

  // List and search: only sessions the caller may read. Filtering after the fact means a page can come back short.
  app.get("/sessions/v1/sessions", async (c) => {
    const res = await upstream(c, cfg.readUrl, "GET", upstreamPath(c));
    if (res instanceof Response || res.status !== 200) return pass(res);
    const page = json(res) ?? {};
    const sessions = (Array.isArray(page.sessions) ? page.sessions : []).filter((s: any) => typeof s?.sessionId === "string" && canRead(c, s.sessionId));
    audit(c, "session.list", "r", null, "allow", "mode", `filtered:${sessions.length}`);
    return pass(res, { ...page, sessions });
  });

  for (const view of READ_VIEWS) {
    app.get(`/sessions/v1/sessions/:id/${view}`, async (c) => gateRead(c, c.req.param("id")) ?? pass(await upstream(c, cfg.readUrl, "GET", upstreamPath(c))));
  }

  // Events inside one session (gated), or a workspace transcript search (`q`), filtered to readable sessions.
  app.get("/sessions/v1/events", async (c) => {
    const ids = c.req.queries("session") ?? [];
    if (ids.length > 1) return deny(c, 400, "relaygate_bad_request", { detail: "at most one session= through relaygate" });
    if (ids.length === 1) return gateRead(c, ids[0]!) ?? pass(await upstream(c, cfg.readUrl, "GET", upstreamPath(c)));
    if (!c.req.query("q")) return deny(c, 400, "relaygate_bad_request", { detail: "session= or q= is required through relaygate" });
    const res = await upstream(c, cfg.readUrl, "GET", upstreamPath(c));
    if (res instanceof Response || res.status !== 200) return pass(res);
    const page = json(res) ?? {};
    const events = (Array.isArray(page.events) ? page.events : []).filter((e: any) => typeof e?.sessionId === "string" && canRead(c, e.sessionId));
    audit(c, "session.search", "r", null, "allow", "mode", `filtered:${events.length}`);
    return pass(res, { ...page, events });
  });

  // Native uploads (the desktop delivery protocol): one JSON batch, possibly gzip or zstd encoded. Every record must
  // name its session, every session must be writable, and the original bytes are forwarded unchanged.
  app.post("/sessions/v1/delivery/batches", async (c) => {
    const raw = Buffer.from(await c.req.arrayBuffer());
    if (raw.length > MAX_UPLOAD) return deny(c, 413, "relaygate_bad_request", { detail: "batch too large" });
    let decoded: Buffer;
    try {
      const enc = (c.req.header("content-encoding") ?? "identity").toLowerCase();
      if (enc === "identity" || enc === "") decoded = raw;
      else if (enc === "gzip") decoded = gunzipSync(raw, { maxOutputLength: MAX_UPLOAD });
      else if (enc === "zstd") decoded = zstdDecompressSync(raw, { maxOutputLength: MAX_UPLOAD });
      else return deny(c, 415, "relaygate_bad_request", { detail: `content-encoding ${enc} not supported` });
    } catch {
      return deny(c, 400, "relaygate_bad_request", { detail: "batch could not be decoded" });
    }
    let body: any;
    try {
      body = JSON.parse(decoded.toString("utf8"));
    } catch {
      return deny(c, 400, "relaygate_bad_request", { detail: "batch is not JSON" });
    }
    const records = body?.batch?.records;
    if (!Array.isArray(records) || records.length === 0) return deny(c, 400, "relaygate_bad_request", { detail: "batch.records[] required" });
    const bySession = new Map<string, unknown[]>();
    for (const r of records) {
      // A record without a session can't be placed in any group, so it is refused rather than let through.
      const id = r?.session_id;
      if (typeof id !== "string" || !SESSION_ID.test(id)) return deny(c, 400, "relaygate_bad_request", { detail: "every record needs a session_id relaygate can gate" });
      bySession.set(id, [...(bySession.get(id) ?? []), r]);
    }
    const { records: _r, ...batchEnvelope } = body.batch;
    const gate = await gateWrites(c, new Map([...bySession].map(([id, rs]) => [id, JSON.stringify({ ...body, batch: { ...batchEnvelope, records: rs } })])));
    if (gate instanceof Response) return gate;
    return pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/delivery/batches", raw));
  });

  // Upload-side housekeeping that carries no session content.
  app.get("/sessions/v1/delivery/limits", async (c) => pass(await upstream(c, cfg.uploadUrl, "GET", "/v1/delivery/limits")));
  app.post("/sessions/v1/auth/token/refresh", async (c) => pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/auth/token/refresh", await c.req.text())));
  app.post("/sessions/v1/onboarding/heartbeat", async (c) => pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/onboarding/heartbeat", await c.req.text())));

  app.all("/sessions/*", (c) => deny(c, 404, "relaygate_route_not_proxied", { path: c.req.path }));
}
