import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { ControlAuth } from "../src/control.js";
import { parsePolicy } from "../src/policy.js";
import { routeSessionsHosts } from "../src/sessions.js";
import { sha256, Store } from "../src/store.js";

const SECRET = "introspect-secret";
const AUD = "https://history.example.test";
const INTERNAL = "read-api-internal-secret";

/** The users relay-control knows, by device token. */
const DEVICES: Record<string, Record<string, unknown>> = {
  sh_at_member: { active: true, principal_type: "desktop-user", sub: "u-member", email: "dev@example.test", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync", "rth:read"], exp: 4_102_444_800 },
  sh_at_inside: { active: true, principal_type: "desktop-user", sub: "u-inside", email: "inside@example.test", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync"], exp: 4_102_444_800 },
  sh_at_otherorg: { active: true, principal_type: "desktop-user", sub: "u-x", org: "org-2", role: "owner", scopes: [] },
  sh_at_revoked: { active: false, reason: "revoked" },
};

function policy() {
  return parsePolicy({
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 33, name: "admins" },
    ],
    enrollmentKeys: [{ id: "local", gid: 11, sha256: sha256("enroll-local-0000000000000000") }],
    sessionDefaults: [
      { gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 33, perm: "r" }] },
      { gid: 22, mode: "660", acl: [{ gid: 11, perm: "w" }, { gid: 33, perm: "r" }] },
    ],
    controlPrincipals: [
      { match: { orgIds: ["org-1"], roles: ["owner", "admin"] }, gid: 33 },
      { match: { orgIds: ["org-1"], emails: ["inside@example.test"] }, gid: 22 },
      { match: { orgIds: ["org-1"], userIds: ["u-inside"] }, gid: 22 },
      { match: { orgIds: ["org-1"] }, gid: 11 },
    ],
    sessionAggregates: { gids: [33] },
  });
}

function harness(opts: { controlDown?: boolean; internalSecret?: string } = {}) {
  const introspections: Array<Record<string, unknown>> = [];
  const control = new Hono();
  control.post("/internal/v1/auth/introspect", async (c) => {
    if (opts.controlDown) return c.json({ error: "down" }, 503);
    if (c.req.header("authorization") !== `Bearer ${SECRET}`) return c.json({ error: "unauthorized" }, 401);
    const body = await c.req.json();
    introspections.push(body);
    return c.json(DEVICES[body.token] ?? { active: false, reason: "unknown" });
  });

  const calls: Array<{ method: string; path: string; auth: string; headers: Headers }> = [];
  const sessions = new Hono();
  sessions.use("*", async (c, next) => {
    calls.push({ method: c.req.method, path: c.req.path + new URL(c.req.url).search, auth: c.req.header("authorization") ?? "", headers: c.req.raw.headers });
    await next();
  });
  let minted = 0;
  sessions.post("/internal/v1/session-read/sessions", async (c) => {
    if (c.req.header("authorization") !== `Bearer ${INTERNAL}`) return c.json({ error: "unauthorized" }, 401);
    const b = await c.req.json();
    return c.json({ userId: b.userId, orgId: b.orgId, workspaceId: b.workspaceId, role: b.role, accessToken: `rth_at_read_${b.userId}_${++minted}`, accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString() });
  });
  sessions.post("/v1/delivery/batches", (c) => c.json({ protocolVersion: 1, receiptId: "rhr_1" }));
  sessions.get("/v1/sessions/:id/events", (c) => c.json({ sessionId: c.req.param("id"), events: [] }, 200, { "x-relayhistory-workspace-id": "ws-1", "access-control-allow-origin": "https://app.example.test" }));
  sessions.get("/v1/sessions/users", (c) => c.json({ users: [{ userId: "u-member" }] }));
  sessions.on("OPTIONS", "*", (c) => c.body(null, 204, { "access-control-allow-origin": "https://app.example.test", "access-control-allow-headers": "authorization" }));

  const toFetch = (app: Hono) => (async (input: RequestInfo | URL, init?: RequestInit) => app.fetch(new Request(input, init))) as typeof fetch;
  const store = new Store(":memory:");
  const pol = policy();
  const controlAuth = new ControlAuth({ introspectUrl: "http://control.test/internal/v1/auth/introspect", introspectSecret: SECRET, audience: AUD, fetch: toFetch(control) }, store);
  const app = createApp({
    store,
    policy: () => pol,
    classifier: () => new RuleClassifier([]),
    control: controlAuth,
    sessions: { uploadUrl: "http://ingest.test", readUrl: "http://read.test", fetch: toFetch(sessions), internalSecret: opts.internalSecret },
  });
  const call = async (method: string, path: string, token?: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await app.request(path, {
      method,
      headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: any = text;
    try {
      parsed = JSON.parse(text);
    } catch {
      /* not JSON */
    }
    return { status: res.status, body: parsed, headers: res.headers };
  };
  const batch = (session_id: string) => ({
    protocolVersion: 1,
    batch: { schema_version: 1, origin_id: "o", batch_id: "b", records: [{ schema_version: 1, record_id: "r", kind: "session_event", source: "claude", session_id, operation: "upsert", payload: { text: "work" } }] },
  });
  const mint = (userId: string, role?: string) =>
    call("POST", "/sessions/internal/v1/session-read/sessions", INTERNAL, { userId, orgId: "org-1", workspaceId: "ws-1", role, audience: AUD, scopes: ["rth:read"] });
  return { app, store, call, batch, mint, introspections, calls };
}

describe("relay-control principals: desktop device tokens", () => {
  it("introspects a device token, maps it by policy, and forwards the token unchanged", async () => {
    const h = harness();
    const up = await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s-dev"));
    expect(up.status).toBe(200);
    expect(h.introspections[0]).toEqual({ token: "sh_at_member", aud: AUD });
    expect(h.calls.at(-1)).toMatchObject({ path: "/v1/delivery/batches", auth: "Bearer sh_at_member" });
    // The session belongs to the Control user, in the group its rule gave.
    const agent = h.store.agentByName("ctl:u-member")!;
    expect(h.store.session("s-dev")).toMatchObject({ owner: agent.id, gid: 11 });
    // Positive answers are cached briefly.
    await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s-dev"));
    expect(h.introspections).toHaveLength(1);
  });

  it("the same policy rules apply: an outside member can't write an inside session", async () => {
    const h = harness();
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("s-pit"))).status).toBe(200);
    expect(h.store.session("s-pit")?.gid).toBe(22);
    // The outside member may write into the inside session (11:w)...
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s-pit"))).status).toBe(200);
    // ...but the inside member can't write the outside member's session.
    await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s-out"));
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("s-out"))).status).toBe(403);
  });

  it("refuses invalid tokens, unmatched users, and fails closed when Control can't answer", async () => {
    const h = harness();
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_revoked", h.batch("s1"))).status).toBe(401);
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_nobody", h.batch("s1"))).status).toBe(401);
    const unmatched = await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_otherorg", h.batch("s1"));
    expect(unmatched.status).toBe(403);
    expect(h.store.session("s1")).toBeUndefined();
    const down = harness({ controlDown: true });
    expect((await down.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", down.batch("s1"))).status).toBe(503);
  });

  it("only applies on Sessions routes: a device token is no relaygate token elsewhere", async () => {
    const h = harness();
    expect((await h.call("GET", "/v1/whoami", "sh_at_member")).status).toBe(401);
  });
});

describe("relay-control principals: dashboard read tokens", () => {
  it("learns read tokens as relay-control mints them through relaygate", async () => {
    const h = harness();
    const minted = await h.mint("u-member");
    expect(minted.status).toBe(200);
    expect(h.calls.at(-1)).toMatchObject({ path: "/internal/v1/session-read/sessions", auth: `Bearer ${INTERNAL}` });
    const token = minted.body.accessToken;
    // Never the token itself at rest.
    expect(JSON.stringify(h.store.controlReadToken(sha256(token), Date.now()))).not.toContain(token);

    await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s-mine"));
    const read = await h.call("GET", "/sessions/v1/sessions/s-mine/events?workspace=ws-1", token);
    expect(read.status).toBe(200);
    expect(read.headers.get("x-relayhistory-workspace-id")).toBe("ws-1");
    expect(h.calls.at(-1)).toMatchObject({ auth: `Bearer ${token}` });
    // An unknown read token is refused.
    expect((await h.call("GET", "/sessions/v1/sessions/s-mine/events", "rth_at_read_forged")).status).toBe(401);
  });

  it("an outside member's read token can't read inside sessions; an admin's (role in the mint) can, and reads aggregates", async () => {
    const h = harness();
    await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("s-pit"));
    const member = (await h.mint("u-member")).body.accessToken;
    const admin = (await h.mint("u-admin", "admin")).body.accessToken;
    expect((await h.call("GET", "/sessions/v1/sessions/s-pit/events", member)).status).toBe(403);
    expect((await h.call("GET", "/sessions/v1/sessions/s-pit/events", admin)).status).toBe(200);
    expect((await h.call("GET", "/sessions/v1/sessions/users?workspace=ws-1", admin)).status).toBe(200);
    expect((await h.call("GET", "/sessions/v1/sessions/users?workspace=ws-1", member)).status).toBe(403);
  });

  it("mints only off the internal path: never through a public Sessions host, and with the internal secret when configured", async () => {
    const h = harness({ internalSecret: INTERNAL });
    const viaHost = routeSessionsHosts(h.app.fetch, ["history.example.test"]);
    const res = await viaHost(
      new Request("http://history.example.test/internal/v1/session-read/sessions", {
        method: "POST",
        headers: { authorization: `Bearer ${INTERNAL}`, "content-type": "application/json", "x-relaygate-host-mounted": "" },
        body: JSON.stringify({ userId: "u-x", orgId: "org-1" }),
      }),
    );
    expect(res.status).toBe(404);
    expect((await h.call("POST", "/sessions/internal/v1/session-read/sessions", "wrong-secret", { userId: "u-x", orgId: "org-1" })).status).toBe(401);
    expect((await h.mint("u-member")).status).toBe(200);
  });

  it("a client can't claim to be host-mounted or not: the marker is set only by the host router", async () => {
    const h = harness();
    const viaHost = routeSessionsHosts(h.app.fetch, ["history.example.test"]);
    // A direct (non-history-host) call with a forged marker still reaches the mint, because the router strips it.
    const res = await viaHost(
      new Request("http://relaygate.test/sessions/internal/v1/session-read/sessions", {
        method: "POST",
        headers: { authorization: `Bearer ${INTERNAL}`, "content-type": "application/json", "x-relaygate-host-mounted": "1" },
        body: JSON.stringify({ userId: "u-member", orgId: "org-1", workspaceId: "ws-1" }),
      }),
    );
    expect(res.status).toBe(200);
  });

  it("passes CORS preflights through for browsers reading Sessions directly", async () => {
    const h = harness();
    const res = await h.call("OPTIONS", "/sessions/v1/sessions/s1/events", undefined, undefined, {
      origin: "https://app.example.test",
      "access-control-request-method": "GET",
      "access-control-request-headers": "authorization",
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.example.test");
    expect(h.calls.at(-1)).toMatchObject({ method: "OPTIONS", auth: "" });
  });
});
