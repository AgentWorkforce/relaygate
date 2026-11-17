import { Hono } from "hono";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { ControlAuth } from "../src/control.js";
import { parsePolicy } from "../src/policy.js";
import { routeSessionsHosts, sessionsAtRoot } from "../src/sessions.js";
import { sha256, Store } from "../src/store.js";

const SECRET = "introspect-secret";
const AUD = "https://history.example.test";
const INTERNAL = "read-api-internal-secret";

/** The users relay-control knows, by device token. */
const DEVICES: Record<string, Record<string, unknown>> = {
  sh_at_member: { active: true, principal_type: "desktop-user", sub: "u-member", email: "dev@example.test", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync", "rth:read", "cli:auth"], exp: 4_102_444_800 },
  sh_at_member2: { active: true, principal_type: "desktop-user", sub: "u-member2", org: "org-1", workspace: "ws-1", role: "member", scopes: ["cli:auth", "rth:sync"], exp: 4_102_444_800 },
  sh_at_inside: { active: true, principal_type: "desktop-user", sub: "u-inside", email: "inside@example.test", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync"], exp: 4_102_444_800 },
  sh_at_otherorg: { active: true, principal_type: "desktop-user", sub: "u-x", org: "org-2", role: "owner", scopes: [] },
  sh_at_revoked: { active: false, reason: "revoked" },
  sh_lt_launch: { active: true, principal_type: "relay_launch", sub: "u-member", org: "org-1", workspace: "ws-1", scopes: ["relay:agent:enrol"], agent_name: "launched-1" },
  sh_lt_noscope: { active: true, principal_type: "relay_launch", sub: "u-member", org: "org-1", workspace: "ws-1", scopes: [], agent_name: "launched-2" },
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
    reservedNamePrefixes: ["control-"],
    // Spawn targets: launching onto an inside node is a cross-group write (classified); the inside group owns it.
    streamDefaults: [{ prefix: "node:", gid: 22, mode: "660", acl: [{ gid: 11, perm: "w" }] }],
  });
}

function harness(opts: { controlDown?: boolean; internalSecret?: string; garbled?: boolean; ceilingOnAdmins?: boolean; policy?: ReturnType<typeof parsePolicy>; store?: Store } = {}) {
  const introspections: Array<Record<string, unknown>> = [];
  const control = new Hono();
  control.post("/internal/v1/auth/introspect", async (c) => {
    if (opts.controlDown) return c.json({ error: "down" }, 503);
    if (opts.garbled) return c.body("not json", 200);
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
  const mintBodies: Array<Record<string, unknown>> = [];
  sessions.post("/internal/v1/session-read/sessions", async (c) => {
    if (c.req.header("authorization") !== `Bearer ${INTERNAL}`) return c.json({ error: "unauthorized" }, 401);
    const b = await c.req.json();
    mintBodies.push(b);
    return c.json({ userId: b.userId, orgId: b.orgId, workspaceId: b.workspaceId, role: b.role, accessToken: `rth_at_read_${b.userId}_${++minted}`, accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString() });
  });
  sessions.post("/v1/delivery/batches", (c) => c.json({ protocolVersion: 1, receiptId: "rhr_1" }));
  sessions.get("/v1/sessions/:id/events", (c) => c.json({ sessionId: c.req.param("id"), events: [] }, 200, { "x-relayhistory-workspace-id": "ws-1", "access-control-allow-origin": "https://app.example.test" }));
  sessions.get("/v1/sessions/users", (c) => c.json({ users: [{ userId: "u-member" }] }));
  sessions.on("OPTIONS", "*", (c) => c.body(null, 204, { "access-control-allow-origin": "https://app.example.test", "access-control-allow-headers": "authorization" }));

  const toFetch = (app: Hono) => (async (input: RequestInfo | URL, init?: RequestInit) => app.fetch(new Request(input, init))) as typeof fetch;
  const store = opts.store ?? new Store(":memory:");
  const pol = opts.policy ? opts.policy : opts.ceilingOnAdmins ? parsePolicy({ ...policy(), ceilings: [{ gid: 33, never: [22] }] }) : policy();
  const controlAuth = new ControlAuth({ introspectUrl: "http://control.test/internal/v1/auth/introspect", introspectSecret: SECRET, audience: AUD, fetch: toFetch(control) }, store);
  const app = createApp({
    store,
    policy: () => pol,
    classifier: () => new RuleClassifier([]),
    control: controlAuth,
    sessions: { uploadUrl: "http://ingest.test", readUrl: "http://read.test", fetch: toFetch(sessions), internalSecret: opts.internalSecret, corsOrigins: ["https://app.example.test"] },
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
  const mint = (userId: string, role?: string, extra: Record<string, unknown> = {}) =>
    call("POST", "/sessions/internal/v1/session-read/sessions", INTERNAL, { userId, orgId: "org-1", workspaceId: "ws-1", role, audience: AUD, scopes: ["rth:read"], ...extra });
  return { app, store, call, batch, mint, mintBodies, introspections, calls, controlAuth };
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

describe("relay-control principals: review regressions", () => {
  it("reserves the ctl: namespace: no enrollment key registers one, and a registered agent never stands for a Control user", async () => {
    const h = harness();
    const reg = await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "ctl:u-member" });
    expect(reg.status).toBe(400);
    // Even an agent that predates the reservation (same name, a real enrollment key) is never reused.
    h.store.createAgent("ctl:u-x2", 11, "local", undefined);
    DEVICES.sh_at_x2 = { active: true, principal_type: "desktop-user", sub: "u-x2", org: "org-1", role: "member", scopes: ["rth:sync"] };
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_x2", h.batch("s-x2"))).status).toBe(403);
    expect(h.store.agentByName("ctl:u-x2")?.gid).toBe(11);
  });

  it("read tokens never upload, and credentials without rth:read never read", async () => {
    const h = harness();
    const token = (await h.mint("u-member")).body.accessToken;
    expect((await h.call("POST", "/sessions/v1/delivery/batches", token, h.batch("s-claim"))).status).toBe(403);
    expect(h.store.session("s-claim")).toBeUndefined();
    // sh_at_inside has rth:sync only.
    expect((await h.call("GET", "/sessions/v1/sessions/s1/events", "sh_at_inside")).status).toBe(403);
  });

  it("a read token minted without an email still matches email rules, from the email relay-control reported for the user", async () => {
    const h = harness();
    await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("s-pit"));
    const token = (await h.mint("u-inside")).body.accessToken;
    expect((await h.controlAuth.identify(token))?.email).toBe("inside@example.test");
  });

  it("an aggregate is never served to a principal under a ceiling", async () => {
    const h = harness({ ceilingOnAdmins: true });
    const admin = (await h.mint("u-admin", "admin")).body.accessToken;
    expect((await h.call("GET", "/sessions/v1/sessions/users", admin)).status).toBe(403);
  });

  it("relaygate's own refusals carry CORS headers for allowed origins", async () => {
    const h = harness();
    const res = await h.call("GET", "/sessions/v1/sessions/s1/events", "rth_at_read_forged", undefined, { origin: "https://app.example.test" });
    expect(res.status).toBe(401);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://app.example.test");
    const other = await h.call("GET", "/sessions/v1/sessions/s1/events", "rth_at_read_forged", undefined, { origin: "https://evil.example.test" });
    expect(other.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("an unreadable introspection answer is Control failing (503), not a bad token", async () => {
    const h = harness({ garbled: true });
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s1"))).status).toBe(503);
  });
});

describe("desktop enrolment: POST /v1/register with a device token", () => {
  it("enrols an agent in the person's group with an expiring token, and recovers it for the same person only", async () => {
    const h = harness();
    const proof = "recovery-proof-0123456789";
    const first = await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-a", recovery: proof });
    expect(first.status).toBe(200);
    expect(first.body).toMatchObject({ gid: 11, user_id: "u-member" });
    expect(String(first.body.token)).toMatch(/^rg_/);
    const exp = Date.parse(first.body.expires_at);
    expect(exp).toBeGreaterThan(Date.now());
    expect(exp).toBeLessThanOrEqual(Date.now() + 24 * 3600 * 1000 + 1000);
    expect((await h.call("GET", "/v1/whoami", first.body.token)).body).toMatchObject({ gid: 11 });
    // Same person, same proof: same agent, new token, old one revoked.
    const again = await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-a", recovery: proof });
    expect(again.body.agent_id).toBe(first.body.agent_id);
    expect((await h.call("GET", "/v1/whoami", first.body.token)).status).toBe(401);
    // Another person, even with the proof, can't take the name; nor can an enrollment key.
    expect((await h.call("POST", "/v1/register", "sh_at_member2", { name: "desk-a", recovery: proof })).status).toBe(409);
    expect((await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "desk-a", recovery: proof })).status).toBe(409);
  });

  it("an expired device-enrolled token is refused", async () => {
    const h = harness();
    const r = await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-b" });
    const agent = h.store.agentByName("desk-b")!;
    const stale = h.store.issueToken(agent.id, Date.now() - 1000);
    expect((await h.call("GET", "/v1/whoami", stale)).status).toBe(401);
    expect((await h.call("GET", "/v1/whoami", r.body.token)).status).toBe(200);
  });

  it("refuses device tokens without cli:auth, people no rule matches, invalid tokens and reserved names", async () => {
    const h = harness();
    expect((await h.call("POST", "/v1/register", "sh_at_inside", { name: "desk-c" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "sh_at_otherorg", { name: "desk-c" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "sh_at_revoked", { name: "desk-c" })).status).toBe(401);
    expect((await h.call("POST", "/v1/register", "sh_at_member", { name: "ctl:u-member" })).status).toBe(400);
  });
});

describe("person vs agent: match.as", () => {
  // Every person may read the pit as a person; the agents they enrol stay local.
  const peoplePolicy = () =>
    parsePolicy({
      ...policy(),
      groups: [...policy().groups, { gid: 44, name: "people" }],
      sessionDefaults: [
        { gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 33, perm: "r" }] },
        { gid: 22, mode: "660", acl: [{ gid: 33, perm: "r" }, { gid: 44, perm: "r" }] },
      ],
      controlPrincipals: [
        { match: { orgIds: ["org-1"], userIds: ["u-inside"] }, gid: 22 },
        { match: { orgIds: ["org-1"], roles: ["owner", "admin"], as: ["person"] }, gid: 33 },
        { match: { orgIds: ["org-1"], as: ["agent"] }, gid: 11 },
        { match: { orgIds: ["org-1"], kinds: ["read"] }, gid: 44 },
        { match: { orgIds: ["org-1"] }, gid: 11 },
      ],
    });

  it("the same user reads the pit from the dashboard, and the agent their desktop enrols can't", async () => {
    const h = harness({ policy: peoplePolicy() });
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("pit-1"))).status).toBe(200);
    const read = (await h.mint("u-member")).body.accessToken;
    expect((await h.call("GET", "/sessions/v1/sessions/pit-1/events", read)).status).toBe(200);
    // The device token sits where the person's agents can reach it: it gets no more than an agent.
    expect((await h.call("GET", "/sessions/v1/sessions/pit-1/events", "sh_at_member")).status).toBe(403);
    // The person's own uploads still land in the local group.
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("mine-1"))).status).toBe(200);
    expect(h.store.session("mine-1")).toMatchObject({ gid: 11 });
    const agent = await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-p", recovery: "recovery-proof-0123456789" });
    expect(agent.body).toMatchObject({ gid: 11 });
    expect((await h.call("GET", "/v1/whoami", agent.body.token)).body.group_names).toEqual(["local"]);
    const asAgent = await h.call("GET", "/sessions/v1/sessions/pit-1/events", undefined, undefined, { "x-relaygate-token": agent.body.token, authorization: `Bearer ${read}` });
    expect(asAgent.status).toBe(403);
  });

  it("a rule limited to agents never maps a person, and the reverse", async () => {
    const only = (as: "person" | "agent") => parsePolicy({ ...policy(), controlPrincipals: [{ match: { as: [as] }, gid: 11 }] });
    const agents = harness({ policy: only("agent") });
    expect((await agents.call("POST", "/v1/register", "sh_at_member", { name: "desk-q", recovery: "recovery-proof-0123456789" })).status).toBe(200);
    expect((await agents.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", agents.batch("x-1"))).status).toBe(403);
    const people = harness({ policy: only("person") });
    expect((await people.call("POST", "/v1/register", "sh_at_member", { name: "desk-r", recovery: "recovery-proof-0123456789" })).status).toBe(403);
    expect((await people.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", people.batch("x-2"))).status).toBe(200);
  });
});

describe("reader_kind: how the reader authenticated to relay-control", () => {
  const readerPolicy = () =>
    parsePolicy({
      ...policy(),
      groups: [...policy().groups, { gid: 44, name: "people" }],
      sessionDefaults: [
        { gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 33, perm: "r" }] },
        { gid: 22, mode: "660", acl: [{ gid: 33, perm: "r" }, { gid: 44, perm: "r" }] },
      ],
      controlPrincipals: [
        { match: { orgIds: ["org-1"], userIds: ["u-inside"] }, gid: 22 },
        { match: { orgIds: ["org-1"], kinds: ["read"], readerKinds: ["browser"] }, gid: 44 },
        { match: { orgIds: ["org-1"] }, gid: 11 },
      ],
    });

  it("only a browser mint reads the pit; mcp, device and unlabelled mints don't, and the read API never sees the field", async () => {
    const h = harness({ policy: readerPolicy() });
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("pit-2"))).status).toBe(200);
    const read = async (extra: Record<string, unknown>) =>
      (await h.call("GET", "/sessions/v1/sessions/pit-2/events", (await h.mint("u-member", undefined, extra)).body.accessToken)).status;
    expect(await read({ reader_kind: "browser" })).toBe(200);
    expect(await read({ reader_kind: "mcp" })).toBe(403);
    expect(await read({ reader_kind: "device" })).toBe(403);
    expect(await read({})).toBe(403);
    expect(await read({ reader_kind: "Browser" })).toBe(403);
    expect(h.mintBodies.length).toBe(5);
    for (const b of h.mintBodies) expect(b).not.toHaveProperty("reader_kind");
    expect(h.mintBodies[0]).toMatchObject({ userId: "u-member", orgId: "org-1", scopes: ["rth:read"] });
  });

  it("a device token never matches a readerKinds rule", async () => {
    const h = harness({ policy: readerPolicy() });
    expect((await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_inside", h.batch("pit-3"))).status).toBe(200);
    expect((await h.call("GET", "/sessions/v1/sessions/pit-3/events", "sh_at_member")).status).toBe(403);
  });
});

describe("person identities (personNames)", () => {
  const personPolicy = () =>
    parsePolicy({
      ...policy(),
      controlPrincipals: [{ match: { orgIds: ["org-1"] }, gid: 11, namePrefix: "desk-" }],
      personNames: { prefix: "person-" },
    });
  const personOf = (userId: string) => `person-${sha256(userId).slice(0, 16)}`;

  it("one person, two computers: one identity, each computer rotating only its own token", async () => {
    const h = harness({ policy: personPolicy() });
    const me = personOf("u-member");
    // Allowed despite the rule's desk- prefix.
    const a = await h.call("POST", "/v1/register", "sh_at_member", { name: me, recovery: "computer-a-proof-0123456789" });
    expect(a.status).toBe(200);
    const b = await h.call("POST", "/v1/register", "sh_at_member", { name: me, recovery: "computer-b-proof-0123456789" });
    expect(b.status).toBe(200);
    expect(b.body.agent_id).toBe(a.body.agent_id);
    expect((await h.call("GET", "/v1/whoami", a.body.token)).status).toBe(200);
    expect((await h.call("GET", "/v1/whoami", b.body.token)).status).toBe(200);
    // Computer A re-registers: its old token ends, B's keeps working.
    const a2 = await h.call("POST", "/v1/register", "sh_at_member", { name: me, recovery: "computer-a-proof-0123456789" });
    expect((await h.call("GET", "/v1/whoami", a.body.token)).status).toBe(401);
    expect((await h.call("GET", "/v1/whoami", a2.body.token)).status).toBe(200);
    expect((await h.call("GET", "/v1/whoami", b.body.token)).status).toBe(200);
  });

  it("refuses a person prefix that can't be an agent name", () => {
    expect(() => parsePolicy({ ...policy(), personNames: { prefix: "person/" } })).toThrow();
    expect(() => parsePolicy({ ...policy(), personNames: { prefix: "ctl:p-" } })).toThrow();
    expect(() => parsePolicy({ ...policy(), personNames: { prefix: "p".repeat(65) } })).toThrow();
  });

  it("nobody else enrols a person name: not another person, not a launch, not an enrollment key", async () => {
    const h = harness({ policy: personPolicy() });
    const me = personOf("u-member");
    expect((await h.call("POST", "/v1/register", "sh_at_member2", { name: me, recovery: "other-proof-0123456789" })).body).toMatchObject({ error: "relaygate_name_scope" });
    expect((await h.call("POST", "/v1/register", "sh_at_member2", { name: "person-anything" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: me })).status).toBe(403);
    // Other desktop agents still follow the rule's prefix, and still need their own recovery proof.
    expect((await h.call("POST", "/v1/register", "sh_at_member", { name: "other-1" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-1", recovery: "desk-proof-0123456789" })).status).toBe(200);
    expect((await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-1", recovery: "wrong-proof-0123456789" })).status).toBe(409);
  });
});

describe("launched agents (relay-control launch credentials)", () => {
  it("a launch credential enrols exactly the agent it names, in the launching person's group", async () => {
    const h = harness();
    expect((await h.call("POST", "/v1/register", "sh_lt_launch", { name: "someone-else" })).status).toBe(403);
    const ok = await h.call("POST", "/v1/register", "sh_lt_launch", { name: "launched-1" });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ gid: 11, user_id: "u-member" });
    expect(h.store.agentByName("launched-1")?.keyId).toBe("launch:u-member");
    // A relaunch (a fresh credential naming the same agent) gets the same agent back, without a recovery proof.
    const again = await h.call("POST", "/v1/register", "sh_lt_launch", { name: "launched-1" });
    expect(again.body.agent_id).toBe(ok.body.agent_id);
    expect((await h.call("POST", "/v1/register", "sh_lt_noscope", { name: "launched-2" })).status).toBe(403);
  });

  it("launched agents refresh their token; desktop and key agents can't", async () => {
    const h = harness();
    const launched = (await h.call("POST", "/v1/register", "sh_lt_launch", { name: "launched-1" })).body.token;
    const refreshed = await h.call("POST", "/v1/token/refresh", launched);
    expect(refreshed.status).toBe(200);
    expect(String(refreshed.body.token)).toMatch(/^rg_/);
    expect((await h.call("GET", "/v1/whoami", launched)).status).toBe(401);
    expect((await h.call("GET", "/v1/whoami", refreshed.body.token)).status).toBe(200);
    const desk = (await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-r" })).body.token;
    expect((await h.call("POST", "/v1/token/refresh", desk)).status).toBe(403);
    const keyed = (await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "keyed-r" })).body.token;
    expect((await h.call("POST", "/v1/token/refresh", keyed)).status).toBe(403);
  });

  it("a launched agent gets 24 h whatever the launch credential's own expiry, and no enrollment key can take it over", async () => {
    DEVICES.sh_lt_short = { active: true, principal_type: "relay_launch", sub: "u-member", org: "org-1", workspace: "ws-1", scopes: ["relay:agent:enrol"], agent_name: "launched-3", exp: Math.floor(Date.now() / 1000) + 60 };
    const h = harness();
    const r = await h.call("POST", "/v1/register", "sh_lt_short", { name: "launched-3", recovery: "recovery-proof-0123456789" });
    expect(Date.parse(r.body.expires_at)).toBeGreaterThan(Date.now() + 23 * 3600 * 1000);
    expect((await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "launched-3", recovery: "recovery-proof-0123456789" })).status).toBe(409);
    expect(() => parsePolicy({ ...policy(), enrollmentKeys: [{ id: "launch:u-member", gid: 11, sha256: sha256("x".repeat(32)) }] })).toThrow(/reserved/);
  });

  it("reserved name prefixes can't be enrolled by anyone", async () => {
    const h = harness();
    expect((await h.call("POST", "/v1/register", "sh_at_member", { name: "control-alice" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "control-alice" })).status).toBe(403);
  });

  it("a control plane checks a spawn at /v1/check as the launching person", async () => {
    const h = harness();
    const asLauncher = await h.call("POST", "/v1/check", "sh_at_member", { op: "w", resource: { kind: "stream", id: "node:ws-1/inside-node" }, content: "run the tests" });
    expect(asLauncher.status).toBe(200);
    expect(asLauncher.body).toEqual({ decision: "allow" });
    // A launch credential is never accepted here (introspecting it would redeem it).
    expect((await h.call("POST", "/v1/check", "sh_lt_launch", { op: "w", resource: { kind: "stream", id: "node:ws-1/x" }, content: "x" })).status).toBe(401);
    // Reading a node stream isn't something the outside group may do.
    expect((await h.call("POST", "/v1/check", "sh_at_member", { op: "r", resource: { kind: "stream", id: "node:ws-1/inside-node" } })).status).toBe(403);
    expect((await h.call("POST", "/v1/check", "sh_at_revoked", { op: "w", resource: { kind: "stream", id: "node:ws-1/x" }, content: "x" })).status).toBe(401);
  });
});

describe("SESSIONS_PORT: Sessions at the root of an internal listener", () => {
  it("serves Sessions paths at the root and allows relay-control's mint there (a public host never does)", async () => {
    const h = harness();
    const internal = sessionsAtRoot(h.app.fetch);
    const mint = await internal(
      new Request("http://relaygate-sessions:8081/internal/v1/session-read/sessions", {
        method: "POST",
        // A forged host-mounted marker is stripped, so it can't turn this into a public request either.
        headers: { authorization: `Bearer ${INTERNAL}`, "content-type": "application/json", "x-relaygate-host-mounted": "1" },
        body: JSON.stringify({ userId: "u-member", orgId: "org-1", workspaceId: "ws-1" }),
      }),
    );
    expect(mint.status).toBe(200);
    const token = ((await mint.json()) as any).accessToken;
    await h.call("POST", "/sessions/v1/delivery/batches", "sh_at_member", h.batch("s-root"));
    const read = await internal(new Request("http://relaygate-sessions:8081/v1/sessions/s-root/events?workspace=ws-1", { headers: { authorization: `Bearer ${token}` } }));
    expect(read.status).toBe(200);
  });
});

describe("GET /v1/whoami: the Control user behind the caller", () => {
  it("a device-enrolled agent's whoami carries the device token's user", async () => {
    const h = harness();
    const r = await h.call("POST", "/v1/register", "sh_at_member2", { name: "desk-w", recovery: "recovery-proof-0123456789" });
    const who = await h.call("GET", "/v1/whoami", r.body.token);
    expect(who.status).toBe(200);
    expect(who.body).toMatchObject({ agent_id: r.body.agent_id, name: "desk-w", user_id: "u-member2" });
    // Self only, and never on the provenance card relaygate stamps on what the agent sends.
    expect(who.body.relaygate).not.toHaveProperty("user_id");
  });

  it("a launched agent's whoami carries the launching person's user", async () => {
    const h = harness();
    const r = await h.call("POST", "/v1/register", "sh_lt_launch", { name: "launched-1" });
    expect((await h.call("GET", "/v1/whoami", r.body.token)).body).toMatchObject({ name: "launched-1", user_id: "u-member" });
    // A refreshed token is the same agent, so the same person.
    const refreshed = await h.call("POST", "/v1/token/refresh", r.body.token);
    expect((await h.call("GET", "/v1/whoami", refreshed.body.token)).body).toMatchObject({ user_id: "u-member" });
  });

  it("a key-enrolled agent's whoami has no user_id", async () => {
    const h = harness();
    const r = await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "keyed-w" });
    const who = await h.call("GET", "/v1/whoami", r.body.token);
    expect(who.status).toBe(200);
    expect(who.body).not.toHaveProperty("user_id");
  });

  it("each caller sees only its own user", async () => {
    const h = harness();
    const a = await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-a1" });
    const b = await h.call("POST", "/v1/register", "sh_at_member2", { name: "desk-b1" });
    expect((await h.call("GET", "/v1/whoami", a.body.token)).body.user_id).toBe("u-member");
    expect((await h.call("GET", "/v1/whoami", b.body.token)).body.user_id).toBe("u-member2");
  });

  it("a persisted registration keeps its user_id across a restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "relaygate-whoami-"));
    try {
      const path = join(dir, "relaygate.db");
      const before = harness({ store: new Store(path) });
      const desk = await before.call("POST", "/v1/register", "sh_at_member", { name: "desk-p", recovery: "recovery-proof-0123456789" });
      const launched = await before.call("POST", "/v1/register", "sh_lt_launch", { name: "launched-1" });
      const keyed = await before.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "keyed-p" });
      before.store.close();
      // A fresh process: new store on the same file, and no introspection behind the answer.
      const after = harness({ store: new Store(path) });
      expect((await after.call("GET", "/v1/whoami", desk.body.token)).body).toMatchObject({ name: "desk-p", user_id: "u-member" });
      expect((await after.call("GET", "/v1/whoami", launched.body.token)).body).toMatchObject({ name: "launched-1", user_id: "u-member" });
      expect((await after.call("GET", "/v1/whoami", keyed.body.token)).body).not.toHaveProperty("user_id");
      expect(after.introspections).toHaveLength(0);
      after.store.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
