import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createApp, resolveStream } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { ControlAuth } from "../src/control.js";
import { explain } from "../src/explain.js";
import { parsePolicy } from "../src/policy.js";
import { RelaycastUpstream } from "../src/relaycast.js";
import { SecretBox, sha256, Store } from "../src/store.js";
import { fakeRelaycast, WORKSPACE_KEY } from "./fakes/relaycast.js";

// Desktop agents enrol with a person's device token and are named by their harness (cursor-, claude-, codex-), so no
// streamDefaults prefix covers their inboxes: the inbox follows the registered agent that owns the name.

const SECRET = "introspect-secret";
const PIT_KEY = "enroll-pit-00000000000000000000";
const DEVICES: Record<string, Record<string, unknown>> = {
  sh_at_one: { active: true, principal_type: "desktop-user", sub: "u-one", org: "org-1", workspace: "ws-1", role: "member", scopes: ["cli:auth"], exp: 4_102_444_800 },
  sh_at_two: { active: true, principal_type: "desktop-user", sub: "u-two", org: "org-1", workspace: "ws-1", role: "member", scopes: ["cli:auth"], exp: 4_102_444_800 },
};

function rawPolicy(extra: Record<string, unknown> = {}) {
  return {
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 44, name: "guest" },
    ],
    enrollmentKeys: [{ id: "pit", gid: 22, sha256: sha256(PIT_KEY), namePrefix: "pit-" }],
    controlPrincipals: [{ match: { orgIds: ["org-1"] }, gid: 11 }],
    streamDefaults: [
      { prefix: "relaycast:inbox/local-", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 44, perm: "r" }] },
      { prefix: "relaycast:inbox/pit-", gid: 22, mode: "660" },
    ],
    ...extra,
  };
}

function harness(extra: Record<string, unknown> = {}) {
  const pol = parsePolicy(rawPolicy(extra));
  const control = new Hono();
  control.post("/introspect", async (c) => c.json(DEVICES[(await c.req.json()).token] ?? { active: false }));
  const store = new Store(":memory:");
  const up = fakeRelaycast();
  const relaycast = new RelaycastUpstream({ url: "http://relaycast.test", workspaceKey: WORKSPACE_KEY, box: new SecretBox("s".repeat(32)), fetch: up.fetchFn }, store);
  const controlAuth = new ControlAuth(
    { introspectUrl: "http://control.test/introspect", introspectSecret: SECRET, audience: "https://history.example.test", fetch: (async (i: RequestInfo | URL, init?: RequestInit) => control.fetch(new Request(i, init))) as typeof fetch },
    store,
  );
  const app = createApp({ store, policy: () => pol, classifier: () => new RuleClassifier([]), relaycast, control: controlAuth });
  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  const enrol = async (credential: string, name: string) => {
    const r = await call("POST", "/v1/register", credential, { name, recovery: "recovery-proof-0123456789" });
    expect(r.status).toBe(200);
    return String(r.body.token);
  };
  const dm = (token: string, to: string) => call("POST", "/v1/dm", token, { to, text: "hi" });
  /** POST /v1/check, with the audited reason (the response carries only the decision). */
  const check = async (token: string, op: "r" | "w", id: string) => {
    const r = await call("POST", "/v1/check", token, { op, resource: { kind: "stream", id }, ...(op === "w" ? { content: "hi" } : {}) });
    const row = store.recentAudit(1)[0];
    return { status: r.status, decision: row?.decision, reason: row?.reason };
  };
  return { pol, store, call, enrol, dm, check };
}

describe("an unplaced inbox follows its registered agent", () => {
  it("two device-enrolled local agents named cursor-x and claude-y can DM each other and read their own inboxes", async () => {
    const h = harness();
    const cursor = await h.enrol("sh_at_one", "cursor-x");
    const claude = await h.enrol("sh_at_two", "claude-y");
    expect(h.store.agentByName("cursor-x")!.keyId).toBe("device:u-one");
    expect((await h.dm(cursor, "claude-y")).status).toBe(201);
    expect((await h.dm(claude, "cursor-x")).status).toBe(201);
    // An agent's own inbox: the owner digit applies.
    expect((await h.call("GET", "/v1/dm/conversations", claude)).body.data.length).toBe(1);
    expect(await h.check(cursor, "w", "relaycast:inbox/claude-y")).toEqual({ status: 200, decision: "allow", reason: "mode:660:agent-inbox" });
  });

  it("a pit agent (gid 22) can't DM them, and they can't DM the pit without a rule saying so", async () => {
    const h = harness();
    const cursor = await h.enrol("sh_at_one", "cursor-x");
    const pit = await h.enrol(PIT_KEY, "pit-a");
    expect((await h.dm(pit, "cursor-x")).status).toBe(403);
    expect((await h.dm(cursor, "pit-a")).status).toBe(403);
    // Even with inboxDefaults mirroring local- (22 may read), the pit never gets w on a gid-11 inbox.
    const m = harness({ inboxDefaults: [{ gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 44, perm: "r" }] }] });
    await m.enrol("sh_at_one", "cursor-x");
    const pit2 = await m.enrol(PIT_KEY, "pit-a");
    expect((await m.dm(pit2, "cursor-x")).status).toBe(403);
    expect(await m.check(pit2, "w", "relaycast:inbox/cursor-x")).toEqual({ status: 403, decision: "deny", reason: "mode:660+acl:22:r:agent-inbox" });
    expect(await m.check(pit2, "r", "relaycast:inbox/cursor-x")).toEqual({ status: 200, decision: "allow", reason: "mode:660+acl:22:r:agent-inbox" });
  });

  it("inboxDefaults sets mode, ACL and classify by the agent's group", () => {
    const pol = parsePolicy(rawPolicy({ inboxDefaults: [{ gid: 11, mode: "640", classify: true, acl: [{ gid: 22, perm: "w" }] }] }));
    const store = new Store(":memory:");
    const a = store.createAgent("codex-z", 11, "device:u-one", undefined);
    expect(resolveStream("relaycast:inbox/codex-z", store, pol)).toEqual({
      id: "relaycast:inbox/codex-z",
      owner: a.id,
      gid: 11,
      mode: "640",
      classify: true,
      acl: [{ gid: 22, perm: "w" }],
      source: "agent-inbox",
    });
  });

  it("explicit streamDefaults and overrides still win", async () => {
    const h = harness({
      streamDefaults: [
        ...rawPolicy().streamDefaults,
        { prefix: "relaycast:inbox/claude-", gid: 22, mode: "660" },
      ],
      streamOverrides: [{ id: "relaycast:inbox/cursor-x", gid: 11, mode: "600" }],
      inboxDefaults: [{ gid: 11, mode: "666" }],
    });
    const cursor = await h.enrol("sh_at_one", "cursor-x");
    const claude = await h.enrol("sh_at_two", "claude-y");
    // claude- is a pit prefix here: the local agent can't write it, whatever its own group.
    expect((await h.dm(cursor, "claude-y")).status).toBe(403);
    // cursor-x has an override with no group write.
    expect((await h.dm(claude, "cursor-x")).status).toBe(403);
    expect(resolveStream("relaycast:inbox/cursor-x", h.store, h.pol)?.source).toBe("override");
    expect(resolveStream("relaycast:inbox/claude-y", h.store, h.pol)?.source).toBe("prefix");
  });

  it("a name no agent has stays unknown_stream, and only inbox ids are derived", async () => {
    const h = harness();
    const cursor = await h.enrol("sh_at_one", "cursor-x");
    expect(await h.check(cursor, "w", "relaycast:inbox/claude-nobody")).toEqual({ status: 403, decision: "deny", reason: "unknown_stream" });
    expect((await h.dm(cursor, "claude-nobody")).status).toBe(403);
    expect(resolveStream("relaycast:channel/cursor-x", h.store, h.pol)).toBeUndefined();
    expect(resolveStream("relaycast:agent/cursor-x", h.store, h.pol)).toBeUndefined();
  });

  it("a relay-control user's synthetic ctl: identity is never a DM recipient through this rule", async () => {
    const h = harness();
    const cursor = await h.enrol("sh_at_one", "cursor-x");
    // What a Sessions upload by a Control-only user creates: an agent row with no token, in the user's group.
    const ctl = h.store.ensureControlAgent("u-two", 11);
    expect(ctl).toMatchObject({ name: "ctl:u-two", keyId: "control", gid: 11 });
    expect(resolveStream("relaycast:inbox/ctl:u-two", h.store, h.pol)).toBeUndefined();
    expect(await h.check(cursor, "w", "relaycast:inbox/ctl:u-two")).toEqual({ status: 403, decision: "deny", reason: "unknown_stream" });
    expect((await h.dm(cursor, "ctl:u-two")).status).toBe(403);
    expect(h.store.upstreamAgent(ctl.id)).toBeUndefined();
  });

  it("directory visibility is unchanged: a derived inbox doesn't show the agent", async () => {
    const h = harness();
    const cursor = await h.enrol("sh_at_one", "cursor-x");
    await h.enrol("sh_at_two", "claude-y");
    const pit = await h.enrol(PIT_KEY, "pit-a");
    const names = async (t: string) => (await h.call("GET", "/v1/agents", t)).body.data.map((a: any) => a.name).sort();
    expect(await names(cursor)).toEqual(["cursor-x"]);
    expect(await names(pit)).toEqual(["pit-a"]);
    expect((await h.call("GET", "/v1/agents/claude-y", cursor)).status).toBe(404);
  });

  it("explain reports the derived inbox", () => {
    const pol = parsePolicy(rawPolicy());
    const store = new Store(":memory:");
    store.createAgent("cursor-x", 11, "device:u-one", undefined);
    store.createAgent("claude-y", 11, "device:u-two", undefined);
    const e = explain(pol, store, { as: { agent: "cursor-x" }, op: "w", resource: { kind: "stream", id: "relaycast:inbox/claude-y" } });
    expect(e).toMatchObject({ decision: "allow", reason: "mode:660:agent-inbox" });
  });
});

describe("policy: inboxDefaults", () => {
  it("must name defined groups, once each", () => {
    expect(() => parsePolicy(rawPolicy({ inboxDefaults: [{ gid: 99, mode: "660" }] }))).toThrow(/inbox default for 99/);
    expect(() => parsePolicy(rawPolicy({ inboxDefaults: [{ gid: 11, mode: "660", acl: [{ gid: 99, perm: "r" }] }] }))).toThrow(/inbox default for 11 \(gid 99\)/);
    expect(() => parsePolicy(rawPolicy({ inboxDefaults: [{ gid: 11, mode: "660" }, { gid: 11, mode: "600" }] }))).toThrow(/more than one entry for gid 11/);
    expect(() => parsePolicy(rawPolicy({ inboxDefaults: [{ gid: 11, mode: "661" }] }))).toThrow();
    expect(parsePolicy(rawPolicy()).inboxDefaults).toEqual([]);
  });
});
