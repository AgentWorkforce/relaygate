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
