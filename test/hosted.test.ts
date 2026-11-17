import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { ControlAuth, controlTokenKind, matchControlRule } from "../src/control.js";
import { explain } from "../src/explain.js";
import { parsePolicy } from "../src/policy.js";
import { sha256, Store } from "../src/store.js";

const SECRET = "introspect-secret";

const hostedCredential = (client: string, agent: string, extra: Record<string, unknown> = {}) => ({
  active: true, principal_type: "relay_hosted", sub: "u-member", email: "dev@example.test", org: "org-1", workspace: "ws-1",
  role: "member", scopes: ["relay:hosted:enrol"], agent_name: agent, client, ...extra,
});

/** What relay-control answers, by credential. Hosted credentials are single-use; the fake doesn't burn them. */
const CREDENTIALS: Record<string, Record<string, unknown>> = {
  sh_at_member: { active: true, principal_type: "desktop-user", sub: "u-member", email: "dev@example.test", org: "org-1", workspace: "ws-1", role: "member", scopes: ["rth:sync", "rth:read", "cli:auth"], exp: 4_102_444_800 },
  sh_ht_cursor: hostedCredential("cursor-cloud", "cursor-cloud-0123456789"),
  sh_ht_cursor_again: hostedCredential("cursor-cloud", "cursor-cloud-0123456789"),
  sh_ht_chatgpt: hostedCredential("chatgpt", "assistant-notes"),
  sh_ht_unknown_client: hostedCredential("some-future-client", "cursor-cloud-x"),
  sh_ht_no_client: hostedCredential("cursor-cloud", "cursor-cloud-y", { client: undefined }),
  sh_ht_noscope: hostedCredential("cursor-cloud", "cursor-cloud-z", { scopes: ["relay:agent:enrol"] }),
  sh_ht_wrong_type: hostedCredential("cursor-cloud", "cursor-cloud-w", { principal_type: "relay_launch" }),
  sh_ht_wrong_prefix: hostedCredential("cursor-cloud", "pit-notes"),
};

const base = {
  groups: [
    { gid: 11, name: "local" },
    { gid: 22, name: "pit" },
    { gid: 33, name: "admins" },
  ],
  enrollmentKeys: [{ id: "local", gid: 11, sha256: sha256("enroll-local-0000000000000000") }],
  // Local inboxes take writes from the pit; nothing else of local's is open to it.
  inboxDefaults: [{ gid: 11, mode: "660", acl: [{ gid: 22, perm: "w" }] }],
  streamDefaults: [{ prefix: "local:", gid: 11, mode: "660", acl: [] }],
  ceilings: [{ gid: 22, never: [33] }],
  reservedNamePrefixes: ["cursor-cloud-"],
};

/** An operator who allowed only Cursor cloud agents, into the pit; the usual catch-all stays last. */
const withCursorRule = () =>
  parsePolicy({
    ...base,
    controlPrincipals: [
      { match: { orgIds: ["org-1"], kinds: ["hosted"], clients: ["cursor-cloud"], as: ["agent"] }, gid: 22, namePrefix: "cursor-cloud-" },
      { match: { orgIds: ["org-1"], roles: ["owner", "admin"] }, gid: 33 },
      { match: { orgIds: ["org-1"] }, gid: 11 },
    ],
  });

/** An install that never configured hosted participants: only the catch-all. */
const catchAllOnly = () => parsePolicy({ ...base, controlPrincipals: [{ match: { orgIds: ["org-1"] }, gid: 11 }] });

function harness(policy = withCursorRule()) {
  const introspections: string[] = [];
  const control = new Hono();
  control.post("/internal/v1/auth/introspect", async (c) => {
    if (c.req.header("authorization") !== `Bearer ${SECRET}`) return c.json({ error: "unauthorized" }, 401);
    const body = await c.req.json();
    introspections.push(body.token);
    return c.json(CREDENTIALS[body.token] ?? { active: false, reason: "unknown" });
  });
  const toFetch = (app: Hono) => (async (input: RequestInfo | URL, init?: RequestInit) => app.fetch(new Request(input, init))) as typeof fetch;
  const store = new Store(":memory:");
  const app = createApp({
    store,
    policy: () => policy,
    classifier: () => new RuleClassifier([]),
    control: new ControlAuth({ introspectUrl: "http://control.test/internal/v1/auth/introspect", introspectSecret: SECRET, audience: "https://history.example.test", fetch: toFetch(control) }, store),
    sessions: { uploadUrl: "http://ingest.test", readUrl: "http://read.test", fetch: toFetch(new Hono()) },
  });
  const call = async (method: string, path: string, token?: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { ...(body === undefined ? {} : { "content-type": "application/json" }), ...(token ? { authorization: `Bearer ${token}` } : {}) },
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
  return { store, call, introspections };
}

describe("hosted participants (relay-control hosted credentials)", () => {
  it("sh_ht_ is the hosted kind", () => {
    expect(controlTokenKind("sh_ht_abc")).toBe("hosted");
    expect(controlTokenKind("sh_lt_abc")).toBe("launch");
  });

  it("fails closed: with only a catch-all rule, a hosted participant is refused, never put in gid 11", async () => {
    const h = harness(catchAllOnly());
    const r = await h.call("POST", "/v1/register", "sh_ht_cursor", { name: "cursor-cloud-0123456789" });
    expect(r.status).toBe(403);
    expect(r.body.error).toBe("relaygate_denied");
    // The refusal names the missing rule, so an operator knows what to add.
    expect(r.body.detail).toMatch(/"kinds": \["hosted"\]/);
    expect(r.body.detail).toMatch(/cursor-cloud/);
    expect(h.store.agentByName("cursor-cloud-0123456789")).toBeUndefined();
    const audit = h.store.auditSince(0, 50).find((row) => row.action === "register");
    expect(audit?.reason).toBe("no_hosted_rule:cursor-cloud");
  });

  it("a rule without kinds, or with other kinds only, never matches a hosted credential", () => {
    const policy = parsePolicy({
      ...base,
      controlPrincipals: [
        { match: { orgIds: ["org-1"], kinds: ["device", "launch"] }, gid: 11 },
        { match: { orgIds: ["org-1"], as: ["agent"] }, gid: 11 },
        { match: {}, gid: 11 },
      ],
    });
    const identity = { kind: "hosted" as const, client: "chatgpt" as const, userId: "u", orgId: "org-1", scopes: [] };
    expect(matchControlRule(identity, policy, "agent")).toBeUndefined();
    expect(matchControlRule(identity, policy, "person")).toBeUndefined();
  });

  it("a matching rule enrols exactly the named agent into the operator's group (the pit)", async () => {
    const h = harness();
    expect((await h.call("POST", "/v1/register", "sh_ht_cursor", { name: "cursor-cloud-other" })).status).toBe(403);
    const ok = await h.call("POST", "/v1/register", "sh_ht_cursor", { name: "cursor-cloud-0123456789" });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ gid: 22, user_id: "u-member" });
    expect(Date.parse(ok.body.expires_at)).toBeGreaterThan(Date.now() + 23 * 3600 * 1000);
    expect(h.store.agentByName("cursor-cloud-0123456789")?.keyId).toBe("hosted:u-member");
    expect((await h.call("GET", "/v1/whoami", ok.body.token)).body).toMatchObject({ name: "cursor-cloud-0123456789", user_id: "u-member" });
    // A rejoin (a fresh credential naming the same agent) gets the same agent back, without a recovery proof.
    const again = await h.call("POST", "/v1/register", "sh_ht_cursor_again", { name: "cursor-cloud-0123456789" });
    expect(again.body.agent_id).toBe(ok.body.agent_id);
  });

  it("clients scope a rule: a ChatGPT participant doesn't match the Cursor rule", async () => {
    const h = harness();
    const r = await h.call("POST", "/v1/register", "sh_ht_chatgpt", { name: "assistant-notes" });
    expect(r.status).toBe(403);
    expect(r.body.detail).toMatch(/chatgpt/);
  });

  it("refuses unknown or missing clients, the wrong scope, the wrong principal type and names outside the rule's prefix", async () => {
    const h = harness();
    expect((await h.call("POST", "/v1/register", "sh_ht_unknown_client", { name: "cursor-cloud-x" })).status).toBe(401);
    expect((await h.call("POST", "/v1/register", "sh_ht_no_client", { name: "cursor-cloud-y" })).status).toBe(401);
    expect((await h.call("POST", "/v1/register", "sh_ht_noscope", { name: "cursor-cloud-z" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "sh_ht_wrong_type", { name: "cursor-cloud-w" })).status).toBe(401);
    expect((await h.call("POST", "/v1/register", "sh_ht_wrong_prefix", { name: "pit-notes" })).status).toBe(403);
  });

  it("a reserved prefix stays closed to desktops and enrollment keys, and nobody else can take a hosted agent's name", async () => {
    const h = harness();
    expect((await h.call("POST", "/v1/register", "sh_at_member", { name: "cursor-cloud-desk" })).status).toBe(403);
    expect((await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "cursor-cloud-key" })).status).toBe(403);
    await h.call("POST", "/v1/register", "sh_ht_cursor", { name: "cursor-cloud-0123456789", recovery: "recovery-proof-0123456789" });
    expect((await h.call("POST", "/v1/register", "enroll-local-0000000000000000", { name: "cursor-cloud-0123456789", recovery: "recovery-proof-0123456789" })).status).toBe(403);
  });

  it("hosted participants refresh their token like launched agents", async () => {
    const h = harness();
    const token = (await h.call("POST", "/v1/register", "sh_ht_cursor", { name: "cursor-cloud-0123456789" })).body.token;
    const refreshed = await h.call("POST", "/v1/token/refresh", token);
    expect(refreshed.status).toBe(200);
    expect((await h.call("GET", "/v1/whoami", token)).status).toBe(401);
    expect((await h.call("GET", "/v1/whoami", refreshed.body.token)).status).toBe(200);
  });

  it("in the pit, a hosted participant writes a local inbox only as the policy allows and never reads local", async () => {
    const h = harness();
    await h.call("POST", "/v1/register", "sh_at_member", { name: "desk-agent" });
    const token = (await h.call("POST", "/v1/register", "sh_ht_cursor", { name: "cursor-cloud-0123456789" })).body.token;
    const check = (op: "r" | "w", id: string) => h.call("POST", "/v1/check", token, { op, resource: { kind: "stream", id }, content: "hello" });
    expect((await check("w", "relaycast:inbox/desk-agent")).body).toEqual({ decision: "allow" });
    expect((await check("r", "relaycast:inbox/desk-agent")).status).toBe(403);
    expect((await check("r", "local:notes")).status).toBe(403);
    expect((await check("w", "local:notes")).status).toBe(403);
  });

  it("a hosted credential is only for /v1/register: Sessions and /v1/check never introspect (redeem) it", async () => {
    const h = harness();
    expect((await h.call("GET", "/sessions/v1/sessions/s-1/events", "sh_ht_cursor")).status).toBe(401);
    expect((await h.call("POST", "/v1/check", "sh_ht_cursor", { op: "w", resource: { kind: "stream", id: "local:notes" }, content: "x" })).status).toBe(401);
    expect(h.introspections).toEqual([]);
  });

  it("policy: clients need the hosted kind, and hosted:* key ids are reserved", () => {
    expect(() => parsePolicy({ ...base, controlPrincipals: [{ match: { clients: ["chatgpt"] }, gid: 22 }] })).toThrow(/clients/);
    expect(() => parsePolicy({ ...base, controlPrincipals: [{ match: { kinds: ["device"], clients: ["chatgpt"] }, gid: 22 }] })).toThrow(/clients/);
    expect(() => parsePolicy({ ...base, controlPrincipals: [{ match: { clients: ["nope"] }, gid: 22 }] })).toThrow();
    expect(() => parsePolicy({ ...base, controlPrincipals: [], enrollmentKeys: [{ id: "hosted:u", gid: 11, sha256: sha256("x".repeat(32)) }] })).toThrow(/reserved/);
  });

  it("explain answers for a hosted participant", () => {
    const policy = withCursorRule();
    const as = (client: "cursor-cloud" | "chatgpt") => ({ control: { userId: "u-member", orgId: "org-1", kind: "hosted" as const, client } });
    expect(explain(policy, undefined, { as: as("cursor-cloud"), op: "w", resource: { kind: "stream", id: "relaycast:inbox/x" } })).toMatchObject({
      subject: { gid: 22, group_names: ["pit"] },
    });
    const refused = explain(policy, undefined, { as: as("chatgpt"), op: "w", resource: { kind: "stream", id: "relaycast:inbox/x" } }) as any;
    expect(JSON.stringify(refused)).toMatch(/no_control_rule/);
  });
});
