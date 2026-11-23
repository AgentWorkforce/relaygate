import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { ControlAuth } from "../src/control.js";
import { parsePolicy } from "../src/policy.js";
import { sha256, Store } from "../src/store.js";
import { UPSTREAM_ASSERTION_HEADER, verifyUpstreamAssertion, type UpstreamAssertionConfig } from "../src/upstream-assertion.js";
import { ASSERTION_PRIVATE_KEY, ASSERTION_PUBLIC_KEY } from "./assertion-fixture.js";

const ADMIN = "admin-token-0123456789abcdef";
const INTERNAL = "read-api-internal-secret";
const DEVICES: Record<string, Record<string, unknown>> = {
  sh_at_member: { active: true, principal_type: "desktop-user", sub: "u-member", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync", "rth:read"] },
  sh_at_inside: { active: true, principal_type: "desktop-user", sub: "u-inside", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync", "rth:read"] },
};

function harness(assertion?: UpstreamAssertionConfig) {
  const control = new Hono();
  control.post("/introspect", async (c) => c.json(DEVICES[(await c.req.json()).token] ?? { active: false }));
  const calls: Array<{ method: string; path: string; auth: string; headers: Headers }> = [];
  const read = new Hono();
  read.use("*", async (c, next) => {
    calls.push({ method: c.req.method, path: c.req.path + new URL(c.req.url).search, auth: c.req.header("authorization") ?? "", headers: c.req.raw.headers });
    await next();
  });
  read.get("/v1/sessions", (c) => {
    if (c.req.header("authorization") !== "Bearer rth_st_read_svc") return c.json({ error: "unauthorized" }, 401);
    return c.req.query("cursor") === "c2"
      ? c.json({ sessions: [{ sessionId: "old-4", userIds: ["u-inside"] }], nextCursor: null })
      : c.json({
          sessions: [
            { sessionId: "old-1", userIds: ["u-member"] },
            { sessionId: "old-2", userIds: [] },
            { sessionId: "old-3", userIds: ["u-stranger"] },
          ],
          nextCursor: "c2",
        });
  });
  read.post("/internal/v1/session-read/sessions", async (c) => {
    const b = await c.req.json();
    return c.json({ userId: b.userId, orgId: b.orgId, workspaceId: b.workspaceId, role: b.role, accessToken: `rth_at_read_${b.userId}`, accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString() });
  });
  read.post("/v1/auth/token/revoke", (c) => c.json({ revoked: true }));
  read.get("/v1/sessions/:id/events", (c) => c.json({ sessionId: c.req.param("id"), events: [] }));
  read.get("/v1/digest/daily", (c) => c.json({ digest: [] }));
  read.get("/v1/digest/weekly", (c) => c.json({ digest: [] }));
  read.get("/v1/delivery/records", (c) => c.json({ records: [] }));
  const ingest = new Hono();
  ingest.use("*", async (c, next) => {
    calls.push({ method: c.req.method, path: c.req.path, auth: c.req.header("authorization") ?? "", headers: c.req.raw.headers });
    await next();
  });
  ingest.get("/v1/delivery/admission", (c) => c.json({ state: "open" }));
  ingest.post("/v1/delivery/sessions/selection", (c) => c.json({ ok: true }));
  ingest.post("/v1/upload-consent", (c) => c.json({ ok: true }));

  const fetchFor = (host: string, app: Hono) => [host, app] as const;
  const routes = new Map([fetchFor("control.test", control), fetchFor("read.test", read), fetchFor("ingest.test", ingest)]);
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    return routes.get(new URL(req.url).host)!.fetch(req);
  }) as typeof fetch;

  const policy = parsePolicy({
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 33, name: "admins" },
    ],
    enrollmentKeys: [{ id: "local", gid: 11, sha256: sha256("enroll-local-0000000000000000") }],
    sessionDefaults: [
      { gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 33, perm: "r" }] },
      { gid: 22, mode: "660", acl: [{ gid: 33, perm: "r" }] },
    ],
    controlPrincipals: [
      { match: { userIds: ["u-admin"] }, gid: 33 },
      { match: { userIds: ["u-inside"] }, gid: 22 },
      { match: { userIds: ["u-member"] }, gid: 11 },
    ],
    sessionAggregates: { gids: [33] },
  });
  const store = new Store(":memory:");
  const app = createApp({
    store,
    policy: () => policy,
    classifier: () => new RuleClassifier([]),
    adminToken: ADMIN,
    control: new ControlAuth({ introspectUrl: "http://control.test/introspect", introspectSecret: "s", audience: "https://history.test", fetch: fetchFn }, store),
    sessions: { uploadUrl: "http://ingest.test", readUrl: "http://read.test", assertion, fetch: fetchFn },
  });
  const call = async (method: string, path: string, token?: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: any = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    return { status: res.status, body: parsed };
  };
  const mint = async (userId: string) =>
    (await call("POST", "/sessions/internal/v1/session-read/sessions", INTERNAL, { userId, orgId: "org-1", workspaceId: "ws-1" })).body.accessToken as string;
  return { store, call, calls, mint };
}

const adoptBody = { readToken: "rth_st_read_svc", orgId: "org-1", workspaceId: "ws-1" };

describe("POST /admin/v1/sessions/adopt", () => {
  it("dry run reports what it would adopt and changes nothing", async () => {
    const h = harness();
    const r = await h.call("POST", "/admin/v1/sessions/adopt?dryRun=1", ADMIN, adoptBody);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ dryRun: true, scanned: 4, alreadyOwned: 0, noUploader: ["old-2"], unmatched: [{ sessionId: "old-3", userId: "u-stranger" }] });
    expect(r.body.adopted).toEqual([
      { sessionId: "old-1", owner: "ctl:u-member", gid: 11 },
      { sessionId: "old-4", owner: "ctl:u-inside", gid: 22 },
    ]);
    expect(h.store.session("old-1")).toBeUndefined();
  });

  it("adopts by uploader, pages through the list, and is idempotent", async () => {
    const h = harness();
    const r = await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, adoptBody);
    expect(r.body.adopted).toHaveLength(2);
    expect(h.store.session("old-4")).toMatchObject({ gid: 22, owner: h.store.agentByName("ctl:u-inside")!.id });
    expect(h.calls.filter((x) => x.path.startsWith("/v1/sessions?")).map((x) => x.path)).toEqual([
      "/v1/sessions?workspace=ws-1&limit=200",
      "/v1/sessions?workspace=ws-1&limit=200&cursor=c2",
    ]);
    const again = await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, adoptBody);
    expect(again.body).toMatchObject({ adopted: [], alreadyOwned: 2 });
    // The adopted session now follows the policy: its uploader reads it, an outside member can't.
    expect((await h.call("GET", "/sessions/v1/sessions/old-4/events", await h.mint("u-inside"))).status).toBe(200);
    expect((await h.call("GET", "/sessions/v1/sessions/old-4/events", await h.mint("u-member"))).status).toBe(404);
  });

  it("reports truncation at maxPages and continues from the returned cursor", async () => {
    const h = harness();
    const first = await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, { ...adoptBody, maxPages: 1 });
    expect(first.body).toMatchObject({ truncated: true, nextCursor: "c2" });
    expect(first.body.adopted.map((a: any) => a.sessionId)).toEqual(["old-1"]);
    const rest = await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, { ...adoptBody, cursor: first.body.nextCursor });
    expect(rest.body).toMatchObject({ truncated: false });
    expect(rest.body.adopted.map((a: any) => a.sessionId)).toEqual(["old-4"]);
  });

  it("needs the admin token, and reports an upstream refusal instead of adopting", async () => {
    const h = harness();
    expect((await h.call("POST", "/admin/v1/sessions/adopt", "rg_nope", adoptBody)).status).toBe(401);
    const bad = await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, { ...adoptBody, readToken: "rth_st_read_wrong" });
    expect(bad.body).toMatchObject({ error: "session list answered 401", adopted: [] });
  });

  it("signs each direct read-API page used for adoption", async () => {
    const kid = "adoption-current";
    const at = 1_800_000_000_000;
    const h = harness({ key: ASSERTION_PRIVATE_KEY, kid, now: () => at });
    expect((await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, adoptBody)).status).toBe(200);
    const pages = h.calls.filter((x) => x.path.startsWith("/v1/sessions?"));
    expect(pages).toHaveLength(2);
    for (const page of pages) {
      const claims = verifyUpstreamAssertion(page.headers.get(UPSTREAM_ASSERTION_HEADER)!, new Map([[kid, ASSERTION_PUBLIC_KEY]]), {
        method: "GET",
        path: page.path,
        credential: "Bearer rth_st_read_svc",
        audience: "session-read-api",
        access: "filter",
        sessionIds: [],
      }, at);
      expect(claims.principal.agent_id).toBe("relaygate:session-adopt");
    }
  });
});

describe("Sessions coverage for gate-only", () => {
  it("serves the desktop's admission, consent and selection calls; selection is a write on each named session", async () => {
    const h = harness();
    expect((await h.call("GET", "/sessions/v1/delivery/admission", "sh_at_member")).status).toBe(200);
    expect((await h.call("POST", "/sessions/v1/upload-consent", "sh_at_member", { consent: true })).status).toBe(200);
    expect((await h.call("POST", "/sessions/v1/delivery/sessions/selection", "sh_at_member", { sessions: [{ source: "claude", session_id: "mine" }], enabled: true })).status).toBe(200);
    await h.call("POST", "/admin/v1/sessions/adopt", ADMIN, adoptBody);
    // old-4 belongs to the inside user: an outside member can't select it.
    expect((await h.call("POST", "/sessions/v1/delivery/sessions/selection", "sh_at_member", { sessions: [{ source: "claude", session_id: "old-4" }], enabled: true })).status).toBe(403);
  });

  it("token revocation and the health check need no principal", async () => {
    const h = harness();
    expect((await h.call("POST", "/sessions/v1/auth/token/revoke", "rth_at_read_anything", { token: "x" })).status).toBe(200);
    expect((await h.call("GET", "/sessions/healthz")).body).toEqual({ ok: true });
  });

  it("every digest and delivery-records read is an aggregate", async () => {
    const h = harness();
    const member = await h.mint("u-member");
    const admin = await h.mint("u-admin");
    for (const path of ["/sessions/v1/digest/daily", "/sessions/v1/digest/weekly", "/sessions/v1/delivery/records"]) {
      expect((await h.call("GET", path, member)).status, path).toBe(403);
      expect((await h.call("GET", path, admin)).status, path).toBe(200);
    }
  });
});
