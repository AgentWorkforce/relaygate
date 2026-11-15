import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { ChainClassifier, ClassifierUnavailable, RuleClassifier, type Classifier } from "../src/classifier.js";
import { modeAllows } from "../src/mode.js";
import { parsePolicy, type Policy } from "../src/policy.js";
import { sha256, Store } from "../src/store.js";

const LOCAL_KEY = "enroll-local-0000000000000000";
const PIT_KEY = "enroll-pit-00000000000000000000";
const BRIDGE_KEY = "enroll-bridge-000000000000000000";

function pitPolicy(): Policy {
  return parsePolicy({
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 33, name: "pit-trusted" },
    ],
    enrollmentKeys: [
      { id: "local", gid: 11, sha256: sha256(LOCAL_KEY) },
      { id: "pit", gid: 22, groups: [33], sha256: sha256(PIT_KEY) },
      { id: "bridge", gid: 22, sha256: sha256(BRIDGE_KEY), namePrefix: "bridge-" },
    ],
    streamDefaults: [
      { prefix: "relaycast:inbox/local-", gid: 11, mode: "664" },
      { prefix: "relaycast:inbox/pit-", gid: 22, mode: "662" },
      { prefix: "slack:", gid: 22, mode: "660", classify: true },
    ],
    classifier: { rules: [{ id: "ssn", pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b" }] },
  });
}

class Fixed implements Classifier {
  constructor(private result: "allow" | "deny" | "error") {}
  async classify() {
    if (this.result === "error") throw new ClassifierUnavailable("timeout");
    return { decision: this.result, reason: "fixed" } as const;
  }
}

function harness(model: Classifier = new Fixed("allow")) {
  const store = new Store(":memory:");
  const policy = pitPolicy();
  const classifier = new ChainClassifier([new RuleClassifier(policy.classifier.rules), model]);
  const app = createApp({ store, policy: () => policy, classifier: () => classifier });
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
  return { store, call, register, check };
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

describe("policy", () => {
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
