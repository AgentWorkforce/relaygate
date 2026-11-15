import { gunzipSync, zstdDecompressSync } from "node:zlib";
import type { Context, Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { decideResource, type Deps, type Env, type ResolvedResource } from "./app.js";
import { matchControlRule } from "./control.js";
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
  /**
   * Browser origins allowed to read Sessions directly (the read API's own CORS list). relaygate adds the CORS headers
   * to responses it produces itself (refusals, errors), so the dashboard sees the real status instead of a CORS error.
   */
  corsOrigins?: string[];
  /** Hosts whose requests are Sessions requests at the root path (no /sessions prefix). */
  hosts?: string[];
  /**
   * The read API's internal secret (READ_API_INTERNAL_SECRET). When set, relaygate checks relay-control's mint calls
   * against it before forwarding them; the read API checks it again either way.
   */
  internalSecret?: string;
  fetch?: typeof fetch;
}

/** Request headers forwarded to Sessions besides Authorization. Trust headers (x-relay-ingest-*) never are. */
const PASS_REQUEST = ["content-type", "content-encoding", "accept", "origin", "x-agent-relay-capture-policy-revision", "x-correlation-id", "idempotency-key"];
/** Response headers passed back to the caller. */
const PASS_RESPONSE = [
  "content-type",
  "retry-after",
  "x-relay-admission",
  "x-relayhistory-workspace-id",
  "x-sessions-read-continuation",
  "x-correlation-id",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-headers",
  "access-control-allow-methods",
  "access-control-expose-headers",
  "access-control-max-age",
  "vary",
];
/** Marks a request that arrived on a Sessions host (set by routeSessionsHosts, never trusted from a client). */
const HOST_MOUNTED = "x-relaygate-host-mounted";
/** The largest upload body relaygate inspects (wire and decoded); Sessions' own cap is 2 MiB. */
const MAX_UPLOAD = 4 * 1024 * 1024;

/**
 * Adds CORS headers to Sessions responses relaygate produces itself (refusals, auth errors) for allowed browser
 * origins. Responses from the read API keep its own CORS headers.
 */
export function sessionsCors(cfg: SessionsConfig) {
  const allowed = new Set((cfg.corsOrigins ?? []).map((o) => o.replace(/\/$/, "")));
  return async (c: Context, next: () => Promise<void>) => {
    await next();
    const origin = c.req.header("origin");
    if (!origin || !allowed.has(origin) || c.res.headers.has("access-control-allow-origin")) return;
    c.res.headers.set("access-control-allow-origin", origin);
    c.res.headers.append("vary", "Origin");
  };
}

/** Serves Sessions paths at the root for the configured hosts, by mapping them under /sessions. */
export function routeSessionsHosts(fetchFn: (req: Request) => Response | Promise<Response>, hosts: string[] = []) {
  const set = new Set(hosts.map((h) => h.toLowerCase()));
  return (req: Request): Response | Promise<Response> => {
    const host = (req.headers.get("host") ?? new URL(req.url).host).toLowerCase().replace(/:\d+$/, "");
    const headers = new Headers(req.headers);
    headers.delete(HOST_MOUNTED);
    if (!set.has(host)) return fetchFn(new Request(req, { headers }));
    const url = new URL(req.url);
    url.pathname = `/sessions${url.pathname}`;
    headers.set(HOST_MOUNTED, "1");
    return fetchFn(new Request(url, { method: req.method, headers, body: req.body, duplex: "half" } as RequestInit));
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
    // A relay-control principal's own credential is what identified it: forward it unchanged.
    if (c.get("viaControl") && auth) return auth;
    if (c.req.header("x-relaygate-token") && auth && !/^Bearer\s+rg_/.test(auth)) return auth;
    return cfg.token ? `Bearer ${cfg.token}` : undefined;
  };

  interface Upstream {
    status: number;
    headers: Headers;
    text: string;
  }

  const upstream = async (c: Ctx, base: string, method: string, path: string, body?: BodyInit, contentType?: string): Promise<Upstream | Response> => {
    const auth = credential(c);
    if (!auth) return deny(c, 401, "relaygate_unauthenticated", { detail: "send your Sessions credential in Authorization and your rg_ token in X-Relaygate-Token" });
    const headers: Record<string, string> = { authorization: auth };
    for (const h of PASS_REQUEST) {
      const v = c.req.header(h);
      if (v) headers[h] = v;
    }
    // A body relaygate rewrote is JSON it serialised itself, whatever the client labelled the original.
    if (contentType) {
      headers["content-type"] = contentType;
      delete headers["content-encoding"];
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
  const upload = async (c: Ctx, path: string, body: unknown) =>
    pass(await upstream(c, cfg.uploadUrl, "POST", path, JSON.stringify(body), "application/json"));

  // No request body is buffered past the cap (Sessions' own limit is 2 MiB).
  app.use(
    "/sessions/*",
    bodyLimit({ maxSize: MAX_UPLOAD, onError: (c) => deny(c, 413, "relaygate_bad_request", { detail: "request body too large" }) }),
  );

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

  // --- relay-control principals ------------------------------------------------------------------------------
  if (deps.control) {
    const control = deps.control;
    // relay-control mints dashboard read tokens through relaygate (its Sessions read URL points here). The call is
    // forwarded unchanged; on success relaygate records the token's hash and the identity the mint named, which is
    // how it later knows who holds the token. Never through a public Sessions host.
    const mint = (path: string, record: boolean) =>
      app.post(`/sessions${path}`, async (c) => {
        if (c.req.header(HOST_MOUNTED)) return deny(c, 404, "relaygate_route_not_proxied");
        const auth = c.req.header("authorization") ?? "";
        if (cfg.internalSecret && auth !== `Bearer ${cfg.internalSecret}`) return deny(c, 401, "relaygate_unauthenticated");
        let res: Response;
        try {
          res = await doFetch(new URL(path.replace(/^\//, ""), slash(cfg.readUrl)), {
            method: "POST",
            headers: { authorization: auth, "content-type": c.req.header("content-type") ?? "application/json" },
            body: await c.req.text(),
          });
        } catch {
          return deny(c, 502, "relaygate_upstream_unavailable");
        }
        const text = await res.text();
        if (record && res.ok) {
          try {
            control.recordMint(JSON.parse(text));
          } catch {
            /* not JSON: nothing to record */
          }
        }
        return new Response(text, { status: res.status, headers: { "content-type": res.headers.get("content-type") ?? "application/json" } });
      });
    mint("/internal/v1/session-read/sessions", true);
    mint("/internal/v1/session-read/sessions/refresh", true);
    mint("/internal/v1/session-read/service-tokens", true);
    mint("/internal/v1/session-read/revoke", false);
  }

  // Revoking a token is always safe, whoever asks; the read API checks the token itself.
  app.post("/sessions/v1/auth/token/revoke", async (c) => {
    try {
      const origin = c.req.header("origin");
      const res = await doFetch(new URL("v1/auth/token/revoke", slash(cfg.readUrl)), {
        method: "POST",
        headers: { authorization: c.req.header("authorization") ?? "", "content-type": c.req.header("content-type") ?? "application/json", ...(origin ? { origin } : {}) },
        body: await c.req.text(),
      });
      // Browsers call this too: the read API's CORS headers come back unchanged.
      const headers = new Headers({ "content-type": res.headers.get("content-type") ?? "application/json" });
      for (const h of PASS_RESPONSE) {
        const v = res.headers.get(h);
        if (v) headers.set(h, v);
      }
      return new Response(await res.text(), { status: res.status, headers });
    } catch {
      return deny(c, 502, "relaygate_upstream_unavailable");
    }
  });
  // The history host's health check answers for relaygate itself.
  app.get("/sessions/healthz", (c) => c.json({ ok: true }));

  // CORS preflights for browsers reading Sessions directly: no credential to check, nothing but headers back.
  app.options("/sessions/*", async (c) => {
    const headers: Record<string, string> = {};
    for (const h of ["origin", "access-control-request-method", "access-control-request-headers"]) {
      const v = c.req.header(h);
      if (v) headers[h] = v;
    }
    try {
      const res = await doFetch(new URL(upstreamPath(c).replace(/^\//, ""), slash(cfg.readUrl)), { method: "OPTIONS", headers });
      const out = new Headers();
      for (const h of PASS_RESPONSE) {
        const v = res.headers.get(h);
        if (v) out.set(h, v);
      }
      return new Response(null, { status: res.status, headers: out });
    } catch {
      return new Response(null, { status: 502 });
    }
  });

  // Aggregates over every session (per-person usage, activity, output, digests): only for the groups the policy
  // names in sessionAggregates, because they can't be filtered per session.
  const aggregate = (path: string) =>
    app.get(`/sessions${path}`, async (c) => {
      const principal = c.get("principal");
      const policy = deps.policy();
      // An aggregate spans every session, so a principal under any ceiling never gets one (it may not see all groups).
      const ceilinged = policy.ceilings.some((cl) => cl.gid === principal.gid || principal.groups.includes(cl.gid));
      const allowed = !ceilinged && policy.sessionAggregates.gids.some((g) => principal.gid === g || principal.groups.includes(g));
      audit(c, "session.aggregate", "r", c.req.path.replace(/^\/sessions/, ""), allowed ? "allow" : "deny", "mode", allowed ? "sessionAggregates" : "not_in_sessionAggregates");
      return allowed ? pass(await upstream(c, cfg.readUrl, "GET", upstreamPath(c))) : deny(c, 403, "relaygate_denied", { op: "r", resource: `sessions${path}` });
    });
  for (const path of ["/v1/sessions/users", "/v1/sessions/activity", "/v1/sessions/summaries/activity", "/v1/sessions/output", "/v1/sessions/titles", "/v1/delivery/records", "/v1/digest/*"]) aggregate(path);

  // Upload-side calls the desktop makes that carry no session content.
  app.get("/sessions/v1/delivery/admission", async (c) => pass(await upstream(c, cfg.uploadUrl, "GET", upstreamPath(c))));
  app.post("/sessions/v1/upload-consent", async (c) => pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/upload-consent", await c.req.text())));
  // Choosing which sessions sync is a write on each session it names.
  app.post("/sessions/v1/delivery/sessions/selection", async (c) => {
    const raw = await c.req.text();
    let body: any;
    try {
      body = JSON.parse(raw);
    } catch {
      return deny(c, 400, "relaygate_bad_request", { detail: "selection is not JSON" });
    }
    const named = Array.isArray(body?.sessions) ? body.sessions : null;
    if (!named || named.some((x: any) => typeof x?.session_id !== "string" || !SESSION_ID.test(x.session_id))) {
      return deny(c, 400, "relaygate_bad_request", { detail: "sessions[] with session_id required" });
    }
    // One serialisation shared by every session the selection names.
    const content = JSON.stringify(body);
    const gate = await gateWrites(c, new Map(named.map((x: any) => [x.session_id, content])));
    if (gate instanceof Response) return gate;
    return pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/delivery/sessions/selection", raw));
  });

  // Upload-side housekeeping that carries no session content.
  app.get("/sessions/v1/delivery/limits", async (c) => pass(await upstream(c, cfg.uploadUrl, "GET", "/v1/delivery/limits")));
  app.post("/sessions/v1/auth/token/refresh", async (c) => pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/auth/token/refresh", await c.req.text())));
  app.post("/sessions/v1/onboarding/heartbeat", async (c) => pass(await upstream(c, cfg.uploadUrl, "POST", "/v1/onboarding/heartbeat", await c.req.text())));

  app.all("/sessions/*", (c) => deny(c, 404, "relaygate_route_not_proxied", { path: c.req.path }));
}

export interface AdoptReport {
  dryRun: boolean;
  scanned: number;
  adopted: Array<{ sessionId: string; owner: string; gid: number }>;
  alreadyOwned: number;
  /** No uploader in the read API's listing: stays unowned (invisible through relaygate). */
  noUploader: string[];
  /** The uploader matches no controlPrincipals rule: stays unowned. */
  unmatched: Array<{ sessionId: string; userId: string }>;
  /** Pages stopped early (upstream error); rerun to continue. */
  error?: string;
  /** Set when the run stopped at maxPages with more to list: pass it back as `cursor` to continue. */
  nextCursor?: string;
  truncated: boolean;
}

/**
 * Gives sessions uploaded before relaygate an owner (docs/contract.md, "Adopting existing sessions"): pages the read
 * API's session list with a read service token, maps each session's uploader (its first userId) through
 * controlPrincipals, and claims it as `ctl:<userId>` in that rule's group. Idempotent; a dry run only reports.
 */
export async function adoptSessions(
  deps: Deps,
  cfg: SessionsConfig,
  opts: { readToken: string; orgId: string; workspaceId: string; dryRun: boolean; maxPages?: number; cursor?: string },
): Promise<AdoptReport> {
  const doFetch = cfg.fetch ?? fetch;
  const base = cfg.readUrl.endsWith("/") ? cfg.readUrl : `${cfg.readUrl}/`;
  const report: AdoptReport = { dryRun: opts.dryRun, scanned: 0, adopted: [], alreadyOwned: 0, noUploader: [], unmatched: [], truncated: false };
  const policy = deps.policy();
  let cursor: string | undefined = opts.cursor;
  const maxPages = opts.maxPages ?? 500;
  for (let page = 0; ; page++) {
    if (page >= maxPages) {
      // Stopped by the cap with more to list: say so, and hand back where to continue.
      report.truncated = true;
      report.nextCursor = cursor;
      break;
    }
    const q = new URLSearchParams({ workspace: opts.workspaceId, limit: "200", ...(cursor ? { cursor } : {}) });
    let body: any;
    try {
      const res = await doFetch(new URL(`v1/sessions?${q}`, base), { headers: { authorization: `Bearer ${opts.readToken}` } });
      if (!res.ok) {
        report.error = `session list answered ${res.status}`;
        break;
      }
      body = await res.json();
    } catch (error) {
      report.error = `session list failed: ${(error as Error).name}`;
      break;
    }
    for (const item of Array.isArray(body?.sessions) ? body.sessions : []) {
      const id = item?.sessionId;
      if (typeof id !== "string" || !SESSION_ID.test(id)) continue;
      report.scanned++;
      if (deps.store.session(id)) {
        report.alreadyOwned++;
        continue;
      }
      const userId = Array.isArray(item.userIds) ? item.userIds.find((u: unknown) => typeof u === "string" && u) : undefined;
      if (!userId) {
        report.noUploader.push(id);
        continue;
      }
      const identity = { kind: "device" as const, userId, email: deps.store.controlEmail(userId), orgId: opts.orgId, workspaceId: opts.workspaceId, scopes: [] };
      const rule = matchControlRule(identity, policy);
      if (!rule) {
        report.unmatched.push({ sessionId: id, userId });
        continue;
      }
      if (!opts.dryRun) {
        let agent;
        try {
          agent = deps.store.ensureControlAgent(userId, rule.gid);
        } catch {
          report.unmatched.push({ sessionId: id, userId });
          continue;
        }
        const claim = deps.store.claimSessions([id], agent.id, rule.gid);
        if (!claim.claimed) {
          report.alreadyOwned++;
          continue;
        }
        deps.store.audit({ agentId: agent.id, action: "session.adopt", op: "w", resourceKind: "session", resourceId: id, decision: "allow", stage: "registration", reason: `uploader:${userId}` });
      }
      report.adopted.push({ sessionId: id, owner: `ctl:${userId}`, gid: rule.gid });
    }
    cursor = typeof body?.nextCursor === "string" && body.nextCursor ? body.nextCursor : undefined;
    if (!cursor) break;
  }
  return report;
}

