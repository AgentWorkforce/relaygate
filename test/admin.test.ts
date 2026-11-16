import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { parsePolicy, type Policy } from "../src/policy.js";
import { sha256, Store } from "../src/store.js";

const ADMIN = "admin-token-0123456789abcdef";
const KEY = "enroll-a-000000000000000000000000";

function policy(mode: string): Policy {
  return parsePolicy({
    groups: [{ gid: 1, name: "a" }, { gid: 2, name: "b" }],
    enrollmentKeys: [{ id: "a", gid: 1, sha256: sha256(KEY) }],
    streamDefaults: [{ prefix: "x:", gid: 2, mode }],
  });
}

describe("GET /admin/v1/audit", () => {
  it("returns content-free rows after a seq, with the agent name and the policy version in force", async () => {
    let pol = policy("660");
    const app = createApp({ store: new Store(":memory:"), policy: () => pol, classifier: () => new RuleClassifier([]), adminToken: ADMIN });
    const call = async (method: string, path: string, token: string, body?: unknown) => {
      const res = await app.request(path, { method, headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: body && JSON.stringify(body) });
      return { status: res.status, body: (await res.json()) as any };
    };
    const tok = (await call("POST", "/v1/register", KEY, { name: "agent-1" })).body.token;
    expect((await call("POST", "/v1/check", tok, { op: "r", resource: { kind: "stream", id: "x:1" } })).status).toBe(403);
    const first = await call("GET", "/admin/v1/audit", ADMIN);
    const v1 = first.body.policy_version;
    expect(v1).toMatch(/^[0-9a-f]{12}$/);
    const denied = first.body.rows.find((r: any) => r.action === "check");
    expect(denied).toMatchObject({ agent_name: "agent-1", decision: "deny", resource_id: "x:1", policy_version: v1 });

    pol = policy("666");
    expect((await call("POST", "/v1/check", tok, { op: "r", resource: { kind: "stream", id: "x:1" } })).status).toBe(200);
    const next = await call("GET", `/admin/v1/audit?after=${denied.seq}&agent=agent-1`, ADMIN);
    expect(next.body.rows).toHaveLength(1);
    expect(next.body.rows[0]).toMatchObject({ decision: "allow" });
    expect(next.body.rows[0].policy_version).not.toBe(v1);

    expect((await call("GET", "/admin/v1/audit", tok)).status).toBe(401);
  });

  it("stamps a decision with the policy it was evaluated under, even if the policy reloads mid-decision", async () => {
    let pol = policy("660");
    let release!: () => void;
    const slow = { classify: () => new Promise<{ decision: "allow"; reason: string }>((r) => (release = () => r({ decision: "allow", reason: "ok" }))) };
    const store = new Store(":memory:");
    const app = createApp({ store, policy: () => pol, classifier: () => slow, adminToken: ADMIN });
    const call = async (path: string, token: string, body?: unknown) =>
      (await app.request(path, { method: body ? "POST" : "GET", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: body && JSON.stringify(body) })).json() as Promise<any>;
    pol = policy("662");
    const tok = (await call("/v1/register", KEY, { name: "agent-1" })).token;
    const before = (await call("/admin/v1/audit", ADMIN)).policy_version;
    const pending = call("/v1/check", tok, { op: "w", resource: { kind: "stream", id: "x:1" }, content: "hi" });
    await new Promise((r) => setTimeout(r, 20));
    pol = policy("666");
    release();
    await pending;
    const row = (await call("/admin/v1/audit", ADMIN)).rows.find((r: any) => r.action === "check");
    expect(row.policy_version).toBe(before);
  });
});

describe("admin API for relay-control (R2)", () => {
  const GUEST = "enroll-guest-00000000000000000000";
  const pol = () =>
    parsePolicy({
      groups: [{ gid: 1, name: "a" }, { gid: 2, name: "b" }, { gid: 4, name: "people" }],
      enrollmentKeys: [
        { id: "a", gid: 1, sha256: sha256(KEY) },
        { id: "guest-1", gid: 2, guest: true, namePrefix: "g-", expiresAt: "2099-01-01T00:00:00Z", sha256: sha256(GUEST) },
        { id: "unused", gid: 1, revoked: true, sha256: sha256("enroll-unused-000000000000000000") },
      ],
      streamDefaults: [{ prefix: "x:", gid: 2, mode: "660", acl: [{ gid: 4, perm: "r" }] }],
      controlPrincipals: [
        { match: { as: ["agent"] }, gid: 1 },
        { match: { kinds: ["read"], readerKinds: ["browser"] }, gid: 4 },
        { match: {}, gid: 1 },
      ],
    });
  const harness = () => {
    let t = Date.parse("2026-11-16T00:00:00Z");
    const p = pol();
    const store = new Store(":memory:");
    const app = createApp({ store, policy: () => p, classifier: () => new RuleClassifier([]), adminToken: ADMIN, now: () => t });
    const call = async (method: string, path: string, token: string, body?: unknown) => {
      const res = await app.request(path, { method, headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: body && JSON.stringify(body) });
      return { status: res.status, body: (await res.json()) as any };
    };
    return { call, p, store, advance: (ms: number) => (t += ms) };
  };

  it("validates a draft with the same rules relaygate loads with, saying where it is wrong", async () => {
    const h = harness();
    const good = await h.call("POST", "/admin/v1/policy/validate", ADMIN, { policy: h.p });
    expect(good.body).toMatchObject({ ok: true });
    expect(good.body.hash).toMatch(/^[0-9a-f]{12}$/);
    const bad = await h.call("POST", "/admin/v1/policy/validate", ADMIN, { policy: { groups: [{ gid: 1, name: "a" }], enrollmentKeys: [{ id: "k", gid: 1, sha256: "nope" }] } });
    expect(bad.body.ok).toBe(false);
    expect(bad.body.errors[0]).toMatchObject({ path: "enrollmentKeys.0.sha256" });
    const unknownGid = await h.call("POST", "/admin/v1/policy/validate", ADMIN, { policy: { groups: [{ gid: 1, name: "a" }], enrollmentKeys: [{ id: "k", gid: 9, sha256: sha256("x") }] } });
    expect(unknownGid.body).toMatchObject({ ok: false, errors: [{ message: expect.stringContaining("gid 9") }] });
    const reserved = await h.call("POST", "/admin/v1/policy/validate", ADMIN, { policy: { groups: [{ gid: 1, name: "a" }], enrollmentKeys: [{ id: "device:u1", gid: 1, sha256: sha256("x") }] } });
    expect(reserved.body.ok).toBe(false);
    expect((await h.call("POST", "/admin/v1/policy/validate", ADMIN, {})).status).toBe(400);
    expect((await h.call("POST", "/admin/v1/policy/validate", "rg_nope", { policy: h.p })).status).toBe(401);
  });

  it("lists each key with its agents, active tokens and last use, never its hash", async () => {
    const h = harness();
    const g = await h.call("POST", "/v1/register", GUEST, { name: "g-1" });
    await h.call("POST", "/v1/register", GUEST, { name: "g-2" });
    h.advance(120_000);
    await h.call("GET", "/v1/whoami", g.body.token);
    const keys = (await h.call("GET", "/admin/v1/keys", ADMIN)).body.keys;
    expect(JSON.stringify(keys)).not.toContain(sha256(GUEST));
    const guest = keys.find((k: any) => k.id === "guest-1");
    expect(guest).toMatchObject({ gid: 2, guest: true, namePrefix: "g-", usable: true, agents: 2, activeTokens: 2, expiresAt: "2099-01-01T00:00:00Z" });
    expect(guest.lastUsedAt).toBe("2026-11-16T00:02:00.000Z");
    expect(keys.find((k: any) => k.id === "unused")).toMatchObject({ revoked: true, usable: false, agents: 0, activeTokens: 0, lastUsedAt: null });
  });

  it("explains a relay-control user as a dashboard person and as the agents they enrol", async () => {
    const h = harness();
    const ask = (control: Record<string, unknown>) => h.call("POST", "/admin/v1/explain", ADMIN, { as: { control: { userId: "u1", orgId: "o1", ...control } }, op: "r", resource: { kind: "stream", id: "x:doc" } });
    const person = (await ask({})).body;
    expect(person).toMatchObject({ decision: "allow", subject: { name: "ctl:u1", gid: 4 } });
    expect(person.steps[0].detail).toContain("controlPrincipals rule 1");
    expect((await ask({ readerKind: "mcp" })).body).toMatchObject({ decision: "deny", subject: { gid: 1 } });
    const agent = (await ask({ kind: "device", as: "agent" })).body;
    expect(agent).toMatchObject({ decision: "deny", subject: { name: "<agent of u1>", gid: 1 } });
    expect(agent.steps[0].detail).toContain("controlPrincipals rule 0");
    // A person who already uploaded owns that session in explain as in a real request.
    const store = (h as any).store as Store;
    const ctl = store.ensureControlAgent("u1", 1);
    store.claimSessions(["s-own"], ctl.id, 1);
    const own = await h.call("POST", "/admin/v1/explain", ADMIN, { as: { control: { userId: "u1", orgId: "o1", readerKind: "mcp" } }, op: "r", resource: { kind: "session", id: "s-own" } });
    expect(own.body).toMatchObject({ decision: "allow" });
    // Against a draft with no rule for them.
    const none = await h.call("POST", "/admin/v1/explain", ADMIN, { policy: { ...h.p, controlPrincipals: [] }, as: { control: { userId: "u1", orgId: "o1" } }, op: "r", resource: { kind: "stream", id: "x:doc" } });
    expect(none.body).toMatchObject({ draft: true, decision: "deny", reason: "no_control_rule" });
  });
});
