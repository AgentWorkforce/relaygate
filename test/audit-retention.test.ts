import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { parsePolicy } from "../src/policy.js";
import { sha256, Store, type AuditEntry } from "../src/store.js";

const ADMIN = "admin-token-0123456789abcdef";
const KEY = "enroll-a-000000000000000000000000";

const read = (over: Partial<AuditEntry> = {}): AuditEntry => ({
  agentId: "ag_1",
  action: "dm.messages",
  op: "r",
  resourceKind: "stream",
  resourceId: "relaycast:inbox/local-a",
  decision: "allow",
  stage: "mode",
  reason: "read",
  policyVersion: "aaaaaaaaaaaa",
  ...over,
});

function clocked(opts: Parameters<Store["configureAudit"]>[0]) {
  const store = new Store(":memory:");
  let t = Date.parse("2026-11-28T00:00:00Z");
  store.clock = () => t;
  store.configureAudit(opts);
  return { store, advance: (ms: number) => (t += ms), rows: () => store.auditSince(0, 1000) };
}

describe("audit coalescing", () => {
  it("adds an agent's repeated allowed reads of one resource to one row within the window", () => {
    const { store, advance, rows } = clocked({ coalesceSeconds: 60 });
    for (let i = 0; i < 50; i++) {
      store.audit(read());
      advance(1000);
    }
    expect(rows()).toHaveLength(1);
    expect(rows()[0]).toMatchObject({ count: 50, at: "2026-11-28T00:00:00.000Z", last_at: "2026-11-28T00:00:49.000Z" });

    // The window closes 60 s after the row opened: the next read opens a new row.
    advance(11_000);
    store.audit(read());
    expect(rows()).toHaveLength(2);
    expect(rows()[1]).toMatchObject({ count: 1, last_at: null });
  });

  it("keeps a row per write, per denial, and per distinct agent, resource, reason or policy version", () => {
    const { store, rows } = clocked({ coalesceSeconds: 60 });
    store.audit(read());
    store.audit(read({ op: "w", action: "dm.send" }));
    store.audit(read({ op: "w", action: "dm.send" }));
    store.audit(read({ decision: "deny", reason: "read_denied" }));
    store.audit(read({ decision: "deny", reason: "read_denied" }));
    store.audit(read({ agentId: "ag_2" }));
    store.audit(read({ resourceId: "relaycast:inbox/local-b" }));
    store.audit(read({ policyVersion: "bbbbbbbbbbbb" }));
    store.audit(read());
    expect(rows()).toHaveLength(8);
    expect(rows()[0]).toMatchObject({ count: 2 });
  });

  it("writes every read when coalescing is off", () => {
    const { store, rows } = clocked({ coalesceSeconds: 0 });
    store.audit(read());
    store.audit(read());
    expect(rows()).toHaveLength(2);
  });

  it("opens a new row when the absorbing row was pruned", () => {
    const { store, rows } = clocked({ coalesceSeconds: 60, maxRows: 1 });
    store.audit(read());
    store.audit(read({ resourceId: "relaycast:inbox/local-b" }));
    expect(store.pruneAudit()).toBe(1);
    store.audit(read());
    expect(rows().map((r) => [r.resource_id, r.count])).toEqual([
      ["relaycast:inbox/local-b", 1],
      ["relaycast:inbox/local-a", 1],
    ]);
  });
});

describe("audit retention", () => {
  it("prunes rows past the retention age, oldest first, in batches", () => {
    const { store, advance, rows } = clocked({ retentionDays: 30 });
    for (let i = 0; i < 7; i++) store.audit(read({ op: "w" }));
    advance(31 * 86_400_000);
    store.audit(read({ op: "w", action: "kept" }));
    expect(store.pruneAudit(3)).toBe(3);
    expect(store.pruneAudit(3)).toBe(3);
    expect(store.pruneAudit(3)).toBe(1);
    expect(store.pruneAudit(3)).toBe(0);
    expect(rows().map((r) => r.action)).toEqual(["kept"]);
  });

  it("prunes everything when every row is past the retention age", () => {
    const { store, advance, rows } = clocked({ retentionDays: 1 });
    store.audit(read({ op: "w" }));
    store.audit(read({ op: "w" }));
    advance(2 * 86_400_000);
    expect(store.pruneAudit()).toBe(2);
    expect(rows()).toHaveLength(0);
  });

  it("keeps about the newest maxRows rows", () => {
    const { store, rows } = clocked({ maxRows: 3 });
    for (let i = 0; i < 10; i++) store.audit(read({ op: "w", action: `a${i}` }));
    expect(store.pruneAudit()).toBe(7);
    expect(rows().map((r) => r.action)).toEqual(["a7", "a8", "a9"]);
  });

  it("prunes nothing with retention and the cap off", () => {
    const { store, advance } = clocked({});
    store.audit(read({ op: "w" }));
    advance(400 * 86_400_000);
    expect(store.pruneAudit()).toBe(0);
  });
});

describe("audit write failures", () => {
  it("never throw, and are counted", () => {
    const store = new Store(":memory:");
    (store as unknown as { db: { exec(sql: string): void } }).db.exec("DROP TABLE audit");
    expect(() => store.audit(read())).not.toThrow();
    expect(store.auditWriteFailures).toBe(1);
  });

  it("do not fail registration or later requests, and the admin audit reports them", async () => {
    const store = new Store(":memory:");
    const policy = parsePolicy({
      groups: [{ gid: 1, name: "a" }],
      enrollmentKeys: [{ id: "a", gid: 1, sha256: sha256(KEY) }],
      streamDefaults: [{ prefix: "x:", gid: 1, mode: "660" }],
    });
    const app = createApp({ store, policy: () => policy, classifier: () => new RuleClassifier([]), adminToken: ADMIN });
    const call = async (method: string, path: string, token: string, body?: unknown) => {
      const res = await app.request(path, { method, headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: body && JSON.stringify(body) });
      return { status: res.status, body: (await res.json()) as any };
    };
    // The audit table stands in for a volume that can no longer take audit rows.
    const db = (store as unknown as { db: { exec(sql: string): void } }).db;
    db.exec("ALTER TABLE audit RENAME TO audit_gone");
    db.exec("CREATE TABLE audit (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, agent_id TEXT, action TEXT NOT NULL CHECK (0), op TEXT, resource_kind TEXT, resource_id TEXT, decision TEXT NOT NULL, stage TEXT, reason TEXT, policy_version TEXT, count INTEGER NOT NULL DEFAULT 1, last_at TEXT)");

    const reg = await call("POST", "/v1/register", KEY, { name: "agent-1" });
    expect(reg.status).toBe(200);
    expect((await call("POST", "/v1/check", reg.body.token, { op: "r", resource: { kind: "stream", id: "x:1" } })).status).toBe(200);
    expect(store.auditWriteFailures).toBe(2);
    expect((await call("GET", "/admin/v1/audit", ADMIN)).body.audit_write_failures).toBe(2);
  });
});
