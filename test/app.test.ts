import { describe, expect, it } from "vitest";
import { createApp, sweepGuestKeys } from "../src/app.js";
import { ChainClassifier, ClassifierUnavailable, RuleClassifier, type Classifier } from "../src/classifier.js";
import { check as checkMode, modeAllows } from "../src/mode.js";
import { parsePolicy, type Policy } from "../src/policy.js";
import { sha256, Store } from "../src/store.js";

const LOCAL_KEY = "enroll-local-0000000000000000";
const PIT_KEY = "enroll-pit-00000000000000000000";
const BRIDGE_KEY = "enroll-bridge-000000000000000000";
const GUEST_KEY = "enroll-guest-0000000000000000000";

const FUTURE = "2099-01-01T00:00:00Z";

/** The pit deployment's defaults from docs/contract.md: 660 everywhere, ACLs for the pit and the guest. */
function pitRaw() {
  return {
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 33, name: "pit-trusted" },
      { gid: 44, name: "guest" },
    ],
    enrollmentKeys: [
      { id: "local", gid: 11, sha256: sha256(LOCAL_KEY) },
      { id: "pit", gid: 22, groups: [33], sha256: sha256(PIT_KEY) },
      { id: "bridge", gid: 22, sha256: sha256(BRIDGE_KEY), namePrefix: "bridge-" },
      { id: "vendor", gid: 44, sha256: sha256(GUEST_KEY), namePrefix: "guest-", guest: true, expiresAt: FUTURE } as Record<string, unknown>,
    ],
    streamDefaults: [
      { prefix: "relaycast:inbox/local-", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }] },
      { prefix: "relaycast:inbox/pit-", gid: 22, mode: "660", acl: [{ gid: 11, perm: "w" }] },
      { prefix: "relaycast:inbox/guest-", gid: 44, mode: "660", acl: [{ gid: 11, perm: "w" }] },
      { prefix: "relaycast:channel/", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }] },
      { prefix: "relaycast:channel/pit-", gid: 22, mode: "660", acl: [{ gid: 11, perm: "w" }] },
      { prefix: "relaycast:channel/collab-", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 44, perm: "rw" }] },
      { prefix: "slack:", gid: 22, mode: "660", classify: true },
    ],
    streamOverrides: [] as Array<Record<string, unknown>>,
    ceilings: [{ gid: 44, never: [22] }],
    classifier: { rules: [{ id: "ssn", pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b" }] },
  };
}

function pitPolicy(edit: (raw: ReturnType<typeof pitRaw>) => void = () => {}): Policy {
  const raw = pitRaw();
  edit(raw);
  return parsePolicy(raw);
}

class Fixed implements Classifier {
  constructor(private result: "allow" | "deny" | "error") {}
  async classify() {
    if (this.result === "error") throw new ClassifierUnavailable("timeout");
    return { decision: this.result, reason: "fixed" } as const;
  }
}

function harness(model: Classifier = new Fixed("allow"), edit?: (raw: ReturnType<typeof pitRaw>) => void) {
  const store = new Store(":memory:");
  let policy = pitPolicy(edit);
  const classifier = new ChainClassifier([new RuleClassifier(policy.classifier.rules), model]);
  const app = createApp({ store, policy: () => policy, classifier: () => classifier });
  const setPolicy = (e: (raw: ReturnType<typeof pitRaw>) => void) => {
    policy = pitPolicy(e);
  };
  const call = (method: string, path: string, token?: string, body?: unknown) =>
    app.request(path, {
      method,
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const register = async (key: string, name: string, recovery?: string) => {
    const res = await call("POST", "/v1/register", key, { name, recovery });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const check = async (token: string, op: "r" | "w", id: string, content?: string) => {
    const res = await call("POST", "/v1/check", token, { op, resource: { kind: "stream", id }, content });
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };
  const token = async (key: string, name: string) => String((await register(key, name)).body.token);
  const putStream = (tok: string, id: string, body: unknown) => call("PUT", `/v1/streams/${encodeURIComponent(id)}`, tok, body);
  return { store, call, register, check, token, putStream, setPolicy, policy: () => policy };
}

describe("mode bits", () => {
  const owner = { agentId: "a", gid: 22, groups: [] };
  const member = { agentId: "b", gid: 22, groups: [] };
  const supplementary = { agentId: "c", gid: 11, groups: [22] };
  const other = { agentId: "d", gid: 11, groups: [] };
  const x = { owner: "a", gid: 22, mode: "642" };
  it("uses the owner, then any group, then other digit", () => {
    expect(modeAllows(owner, x, "w")).toBe(true);
    expect(modeAllows(member, x, "r")).toBe(true);
    expect(modeAllows(member, x, "w")).toBe(false);
    expect(modeAllows(supplementary, x, "r")).toBe(true);
    expect(modeAllows(other, x, "r")).toBe(false);
    expect(modeAllows(other, x, "w")).toBe(true);
  });
});

describe("access lists and ceilings", () => {
  const guest = { agentId: "g", gid: 44, groups: [] };
  const pit = { agentId: "p", gid: 22, groups: [] };
  it("ACL entries only add access, never remove what other gave", () => {
    const x = { owner: "a", gid: 11, mode: "664", acl: [{ gid: 44, perm: "w" as const }] };
    expect(modeAllows(guest, x, "r")).toBe(true);
    expect(modeAllows(guest, x, "w")).toBe(true);
    expect(modeAllows(pit, x, "w")).toBe(false);
  });
  it("ACLs don't apply to the owner", () => {
    const x = { owner: "g", gid: 44, mode: "460", acl: [{ gid: 44, perm: "rw" as const }] };
    expect(modeAllows(guest, x, "w")).toBe(false);
  });
  it("a ceiling is the last step and refuses whatever mode and ACL allowed", () => {
    const x = { owner: null, gid: 22, mode: "666", acl: [{ gid: 44, perm: "rw" as const }] };
    const res = checkMode(guest, x, "r", [{ gid: 44, never: [22] }]);
    expect(res.allowed).toBe(false);
    expect(res.reason).toBe("ceiling:44->22");
    expect(res.steps.map((s) => s.step)).toEqual(["other", "acl", "ceiling"]);
  });
  it("a ceiling applies through supplementary groups too", () => {
    const x = { owner: null, gid: 22, mode: "666" };
    expect(checkMode({ agentId: "s", gid: 11, groups: [44] }, x, "r", [{ gid: 44, never: [22] }]).allowed).toBe(false);
  });
});

describe("policy", () => {
  it("parses the example pit policy", async () => {
    const { readFileSync } = await import("node:fs");
    const text = readFileSync(new URL("../examples/policy.pit.json", import.meta.url), "utf8").replace(/<sha256[^>]*>/g, "0".repeat(64));
    const policy = parsePolicy(JSON.parse(text));
    expect(policy.streamDefaults.every((d) => d.mode.endsWith("0"))).toBe(true);
    expect(policy.ceilings).toEqual([{ gid: 44, never: [22] }]);
  });

  it("rejects ACLs and ceilings naming unknown groups", () => {
    expect(() => pitPolicy((r) => (r.streamDefaults[0]!.acl = [{ gid: 99, perm: "r" }]))).toThrow(/gid 99/);
    expect(() => pitPolicy((r) => (r.ceilings = [{ gid: 44, never: [98] }]))).toThrow(/gid 98/);
  });

  it("rejects a key that enrolls into a group its own ceiling forbids", () => {
    expect(() => pitPolicy((r) => ((r.enrollmentKeys[3] as Record<string, unknown>).groups = [22]))).toThrow(/ceiling/);
  });

  it("rejects the reserved 1 bit and unknown groups", () => {
    expect(() => parsePolicy({ ...pitPolicy(), streamDefaults: [{ prefix: "x:", gid: 22, mode: "761" }] })).toThrow();
    expect(() => parsePolicy({ ...pitPolicy(), streamDefaults: [{ prefix: "x:", gid: 99, mode: "660" }] })).toThrow(/gid 99/);
  });
});

describe("registration", () => {
  it("issues an rg_ token in the key's group", async () => {
    const h = harness();
    const r = await h.register(PIT_KEY, "pit-a");
    expect(r.status).toBe(200);
    expect(r.body.gid).toBe(22);
    expect(String(r.body.token)).toMatch(/^rg_/);
    const who = await (await h.call("GET", "/v1/whoami", String(r.body.token))).json();
    expect(who.group_names).toEqual(["pit", "pit-trusted"]);
  });

  it("refuses a bad key, a name outside the key's prefix, and a taken name", async () => {
    const h = harness();
    expect((await h.register("nope", "x")).status).toBe(401);
    expect((await h.register(BRIDGE_KEY, "pit-x")).body.error).toBe("relaygate_name_scope");
    await h.register(PIT_KEY, "pit-a");
    expect((await h.register(PIT_KEY, "pit-a")).body.error).toBe("relaygate_name_taken");
  });

  it("recovers the same agent with the recovery proof and revokes the old token", async () => {
    const h = harness();
    const proof = "recovery-proof-0123456789";
    const first = await h.register(BRIDGE_KEY, "bridge-t1", proof);
    const again = await h.register(BRIDGE_KEY, "bridge-t1", proof);
    expect(again.status).toBe(200);
    expect(again.body.agent_id).toBe(first.body.agent_id);
    expect((await h.call("GET", "/v1/whoami", String(first.body.token))).status).toBe(401);
    expect((await h.call("GET", "/v1/whoami", String(again.body.token))).status).toBe(200);
    expect((await h.register(BRIDGE_KEY, "bridge-t1", "wrong-proof-000000000")).status).toBe(409);
    expect((await h.register(LOCAL_KEY, "bridge-t1", proof)).status).toBe(409);
  });
});

describe("the pit rules through /v1/check", () => {
  it("a local agent can message a pit agent, and the pit agent can't answer", async () => {
    const h = harness();
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);
    const pit = String((await h.register(PIT_KEY, "pit-1")).body.token);

    expect((await h.check(local, "w", "relaycast:inbox/pit-1", "can you review PR 12?")).status).toBe(200);
    expect((await h.check(local, "r", "relaycast:inbox/pit-1")).status).toBe(403);
    const reply = await h.check(pit, "w", "relaycast:inbox/local-1", "done");
    expect(reply.status).toBe(403);
    expect(reply.body.error).toBe("relaygate_denied");
    expect((await h.check(pit, "r", "relaycast:inbox/local-1")).status).toBe(200);
  });

  it("only the pit writes to slack, and every slack post is classified", async () => {
    const h = harness(new Fixed("deny"));
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);
    const bridge = String((await h.register(BRIDGE_KEY, "bridge-1")).body.token);
    expect((await h.check(local, "w", "slack:T1/C1/1.1", "hi")).body.error).toBe("relaygate_denied");
    // Same group as the stream, but classify is on: the (denying) model still runs.
    expect((await h.check(bridge, "w", "slack:T1/C1/1.1", "hi")).body.error).toBe("relaygate_classified");
  });

  it("rules deny before the model; a cross-group write needs content", async () => {
    const h = harness();
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);
    const res = await h.check(local, "w", "relaycast:inbox/pit-1", "patient ssn is 123-45-6789");
    expect(res.body.error).toBe("relaygate_classified");
    expect((await h.check(local, "w", "relaycast:inbox/pit-1")).status).toBe(400);
  });

  it("a classifier failure is 503, never an allow", async () => {
    const h = harness(new Fixed("error"));
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);
    const res = await h.check(local, "w", "relaycast:inbox/pit-1", "hello");
    expect(res.status).toBe(503);
    expect(res.body.error).toBe("relaygate_unavailable");
  });

  it("an unknown stream is denied", async () => {
    const h = harness();
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);
    expect((await h.check(local, "r", "nowhere:1")).status).toBe(403);
  });
});

describe("stream registration", () => {
  it("lets a component register only under its own group's prefix, and only the owner change it", async () => {
    const h = harness();
    const bridge = String((await h.register(BRIDGE_KEY, "bridge-1")).body.token);
    const other = String((await h.register(PIT_KEY, "pit-2")).body.token);
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);

    expect((await h.call("PUT", `/v1/streams/${encodeURIComponent("slack:T1/C2/9.9")}`, bridge, { mode: "600", classify: true })).status).toBe(200);
    expect((await h.call("PUT", `/v1/streams/${encodeURIComponent("slack:T1/C2/9.9")}`, other, { mode: "666" })).status).toBe(403);
    expect((await h.call("PUT", `/v1/streams/${encodeURIComponent("slack:T1/C3/1.0")}`, local, { mode: "666" })).status).toBe(403);
    // mode 600: the owner may post, other pit members may not.
    expect((await h.check(other, "w", "slack:T1/C2/9.9", "x")).body.error).toBe("relaygate_denied");
  });

  it("audits decisions without content", async () => {
    const h = harness();
    const local = String((await h.register(LOCAL_KEY, "local-1")).body.token);
    await h.check(local, "w", "relaycast:inbox/pit-1", "secret words here");
    const rows = h.store.recentAudit(10);
    expect(JSON.stringify(rows)).not.toContain("secret words here");
    expect(rows.some((r) => r.action === "check" && r.decision === "allow")).toBe(true);
  });
});

describe("guests", () => {
  it("a guest writes and reads the collab channel, classified as a guest", async () => {
    const seen: unknown[] = [];
    const spy: Classifier = { classify: async (input) => (seen.push(input.from), { decision: "allow", reason: "ok" }) };
    const h = harness(spy);
    const guest = await h.token(GUEST_KEY, "guest-1");
    const local = await h.token(LOCAL_KEY, "local-1");
    const pit = await h.token(PIT_KEY, "pit-1");

    expect((await h.check(guest, "w", "relaycast:channel/collab-design", "proposal v2 attached")).status).toBe(200);
    expect(seen).toEqual([expect.objectContaining({ name: "guest-1", groups: ["guest"], guest: true })]);
    expect((await h.check(guest, "r", "relaycast:channel/collab-design")).status).toBe(200);
    expect((await h.check(local, "w", "relaycast:channel/collab-design", "thanks")).status).toBe(200);
    // The pit may read the shared channel but, as everywhere, not write outside the pit.
    expect((await h.check(pit, "r", "relaycast:channel/collab-design")).status).toBe(200);
    expect((await h.check(pit, "w", "relaycast:channel/collab-design", "x")).status).toBe(403);
  });

  it("a guest can't read or write local inboxes or ordinary local channels", async () => {
    const h = harness();
    const guest = await h.token(GUEST_KEY, "guest-1");
    for (const id of ["relaycast:inbox/local-1", "relaycast:channel/general"]) {
      expect((await h.check(guest, "r", id)).status).toBe(403);
      expect((await h.check(guest, "w", id, "hi")).status).toBe(403);
    }
  });

  it("local agents answer a guest in its inbox but can't read it", async () => {
    const h = harness();
    const guest = await h.token(GUEST_KEY, "guest-1");
    const local = await h.token(LOCAL_KEY, "local-1");
    expect((await h.check(guest, "r", "relaycast:inbox/guest-1")).status).toBe(200);
    expect((await h.check(local, "w", "relaycast:inbox/guest-1", "see channel")).status).toBe(200);
    expect((await h.check(local, "r", "relaycast:inbox/guest-1")).status).toBe(403);
  });

  it("a guest can never touch gid 22, even with a mistaken override or a stream a pit agent opened up", async () => {
    const h = harness(new Fixed("allow"), (r) => {
      r.streamOverrides = [{ id: "relaycast:channel/pit-oops", gid: 22, mode: "666", acl: [{ gid: 44, perm: "rw" }] }];
    });
    const guest = await h.token(GUEST_KEY, "guest-1");
    const pit = await h.token(PIT_KEY, "pit-1");
    expect((await h.putStream(pit, "relaycast:channel/pit-open", { mode: "666", acl: [{ gid: 44, perm: "rw" }] })).status).toBe(200);

    for (const id of ["relaycast:channel/pit-oops", "relaycast:channel/pit-open", "relaycast:inbox/pit-1", "slack:T1/C1/1.1"]) {
      expect((await h.check(guest, "r", id)).status).toBe(403);
      const w = await h.check(guest, "w", id, "hello");
      expect(w.status).toBe(403);
      expect(w.body.error).toBe("relaygate_denied");
    }
    const reasons = h.store.recentAudit(50).filter((r) => r.resource_id === "relaycast:channel/pit-oops").map((r) => r.reason);
    expect(reasons).toContain("ceiling:44->22:override");
    // The same override still lets local agents in through "other".
    const local = await h.token(LOCAL_KEY, "local-1");
    expect((await h.check(local, "r", "relaycast:channel/pit-oops")).status).toBe(200);
  });

  it("whoami and provenance mark the guest", async () => {
    const h = harness();
    const guest = await h.token(GUEST_KEY, "guest-1");
    const who = await (await h.call("GET", "/v1/whoami", guest)).json();
    expect(who.guest).toBe(true);
    expect(who.relaygate).toEqual({ agent: "guest-1", groups: ["guest"], guest: true });
    const local = await h.token(LOCAL_KEY, "local-1");
    const lwho = await (await h.call("GET", "/v1/whoami", local)).json();
    expect(lwho.guest).toBe(false);
    expect(lwho.relaygate).toEqual({ agent: "local-1", groups: ["local"] });
  });
});

describe("enrollment key lifecycle", () => {
  const guestKey = (r: ReturnType<typeof pitRaw>) => r.enrollmentKeys[3] as Record<string, unknown>;

  it("an expired key enrolls no one", async () => {
    const h = harness(new Fixed("allow"), (r) => (guestKey(r).expiresAt = "2020-01-01T00:00:00Z"));
    expect((await h.register(GUEST_KEY, "guest-1")).status).toBe(401);
    expect(h.store.recentAudit(1)[0]?.reason).toBe("key_expired:vendor");
  });

  it("revoking a guest key ends its tokens for good", async () => {
    const h = harness();
    const guest = await h.token(GUEST_KEY, "guest-1");
    expect((await h.call("GET", "/v1/whoami", guest)).status).toBe(200);
    h.setPolicy((r) => (guestKey(r).revoked = true));
    expect((await h.call("GET", "/v1/whoami", guest)).status).toBe(401);
    // Un-revoking the key doesn't bring the old token back.
    h.setPolicy(() => {});
    expect((await h.call("GET", "/v1/whoami", guest)).status).toBe(401);
  });

  it("an expired or removed guest key ends its tokens", async () => {
    const h = harness();
    const a = await h.token(GUEST_KEY, "guest-a");
    h.setPolicy((r) => (guestKey(r).expiresAt = "2020-01-01T00:00:00Z"));
    expect((await h.check(a, "r", "relaycast:channel/collab-x")).status).toBe(401);

    const h2 = harness();
    const b = await h2.token(GUEST_KEY, "guest-b");
    h2.setPolicy((r) => r.enrollmentKeys.splice(3, 1));
    expect((await h2.call("GET", "/v1/whoami", b)).status).toBe(401);
  });

  it("the sweep revokes guest tokens without waiting for them to be used", async () => {
    const h = harness();
    await h.token(GUEST_KEY, "guest-1");
    await h.token(LOCAL_KEY, "local-1");
    h.setPolicy((r) => (guestKey(r).revoked = true));
    expect(sweepGuestKeys(h.store, h.policy(), Date.now())).toHaveLength(1);
    expect(sweepGuestKeys(h.store, h.policy(), Date.now())).toHaveLength(0);
  });

  it("revoking an ordinary key stops new registrations and leaves existing agents working", async () => {
    const h = harness();
    const local = await h.token(LOCAL_KEY, "local-1");
    h.setPolicy((r) => (r.enrollmentKeys[0]!.revoked = true));
    expect((await h.register(LOCAL_KEY, "local-2")).status).toBe(401);
    expect((await h.call("GET", "/v1/whoami", local)).status).toBe(200);
  });

  it("a recovery can't move a name between a guest key and a member key", async () => {
    const h = harness(new Fixed("allow"), (r) => {
      r.enrollmentKeys.push({ id: "guest-open", gid: 44, sha256: sha256("enroll-guest-member-000000000000") } as never);
    });
    const proof = "recovery-proof-0123456789";
    expect((await h.register(GUEST_KEY, "guest-1", proof)).status).toBe(200);
    expect((await h.register("enroll-guest-member-000000000000", "guest-1", proof)).status).toBe(409);
  });
});

describe("stream registration with ACLs", () => {
  it("stores the ACL and refuses unknown gids", async () => {
    const h = harness();
    const local = await h.token(LOCAL_KEY, "local-1");
    const guest = await h.token(GUEST_KEY, "guest-1");
    expect((await h.putStream(local, "relaycast:channel/spec", { mode: "660", acl: [{ gid: 99, perm: "r" }] })).status).toBe(400);
    expect((await h.check(guest, "r", "relaycast:channel/spec")).status).toBe(403);
    expect((await h.putStream(local, "relaycast:channel/spec", { mode: "660", acl: [{ gid: 44, perm: "r" }] })).status).toBe(200);
    expect((await h.check(guest, "r", "relaycast:channel/spec")).status).toBe(200);
    expect((await h.check(guest, "w", "relaycast:channel/spec", "x")).status).toBe(403);
  });
});

describe("database from build 1", () => {
  it("adds the new columns to an existing database", async () => {
    const { DatabaseSync } = await import("node:sqlite");
    const { mkdtempSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const path = join(mkdtempSync(join(tmpdir(), "rg-")), "old.db");
    const old = new DatabaseSync(path);
    old.exec(`CREATE TABLE agents (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, gid INTEGER NOT NULL, key_id TEXT NOT NULL, recovery_hash TEXT, created_at TEXT NOT NULL);
      CREATE TABLE streams (id TEXT PRIMARY KEY, owner TEXT NOT NULL, gid INTEGER NOT NULL, mode TEXT NOT NULL, classify INTEGER NOT NULL, updated_at TEXT NOT NULL);
      INSERT INTO agents VALUES ('ag_1', 'local-1', 11, 'local', NULL, 'x');
      INSERT INTO streams VALUES ('relaycast:channel/a', 'ag_1', 11, '660', 0, 'x');`);
    old.close();
    const store = new Store(path);
    expect(store.agentByName("local-1")?.guest).toBe(false);
    expect(store.stream("relaycast:channel/a")?.acl).toEqual([]);
    store.close();
  });
});
