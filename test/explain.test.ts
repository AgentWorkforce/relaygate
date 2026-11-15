import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { RuleClassifier } from "../src/classifier.js";
import { explain, runCases } from "../src/explain.js";
import { parsePolicy } from "../src/policy.js";
import { Store } from "../src/store.js";

const ADMIN = "admin-token-0123456789abcdef";
const NOW = Date.parse("2026-11-14T00:00:00Z");

function examplePolicyRaw() {
  const text = readFileSync(new URL("../examples/policy.pit.json", import.meta.url), "utf8").replace(/<sha256[^>]*>/g, "0".repeat(64));
  return JSON.parse(text);
}
const examplePolicy = () => parsePolicy(examplePolicyRaw());
const exampleCases = () => JSON.parse(readFileSync(new URL("../examples/cases.pit.json", import.meta.url), "utf8")).cases;

describe("explain", () => {
  it("passes every case in examples/cases.pit.json against the example policy", () => {
    const results = runCases(examplePolicy(), undefined, exampleCases(), NOW);
    expect(results.filter((r) => !r.pass).map((r) => r.case.note)).toEqual([]);
  });

  it("says why: a mistaken ACL into the pit is refused by the ceiling", () => {
    const raw = examplePolicyRaw();
    raw.streamOverrides = [{ id: "relaycast:channel/pit-oops", gid: 22, mode: "660", acl: [{ gid: 44, perm: "rw" }] }];
    const e = explain(parsePolicy(raw), undefined, { as: { key: "vendor-guest" }, op: "r", resource: { kind: "stream", id: "relaycast:channel/pit-oops" } }, NOW);
    expect(e.decision).toBe("deny");
    expect(e.reason).toBe("ceiling:44->22:override");
    expect(e.steps.map((s) => s.step)).toEqual(["subject", "resource", "other", "acl", "ceiling"]);
    expect(e.summary).toMatch(/refused by a ceiling/);
  });

  it("reports when the classifier would run", () => {
    const p = examplePolicy();
    const write = explain(p, undefined, { as: { key: "local" }, op: "w", resource: { kind: "stream", id: "relaycast:inbox/pit-a" } }, NOW);
    expect(write).toMatchObject({ decision: "allow", classified: true });
    const same = explain(p, undefined, { as: { key: "local" }, op: "w", resource: { kind: "stream", id: "relaycast:channel/general" } }, NOW);
    expect(same).toMatchObject({ decision: "allow", classified: false });
  });

  it("explains subjects by registered agent, key or groups, and refuses unknown or ended ones", () => {
    const p = examplePolicy();
    const store = new Store(":memory:");
    store.createAgent("pit-a", 22, "pit", undefined);
    const q = (as: object) => explain(p, store, { as: as as never, op: "r", resource: { kind: "stream", id: "relaycast:inbox/local-x" } }, NOW);
    expect(q({ agent: "pit-a" }).decision).toBe("allow");
    expect(q({ gid: 44 }).decision).toBe("deny");
    expect(q({ gid: 11, groups: [22] }).decision).toBe("allow");
    expect(q({ agent: "nobody" }).reason).toBe("unknown_agent");
    expect(q({ key: "nope" }).reason).toBe("unknown_key");
    expect(q({ key: "pit", name: "local-sneaky" }).reason).toBe("name_scope");
    expect(q({ gid: 99 }).reason).toBe("unknown_gid");
    const later = Date.parse("2028-01-01T00:00:00Z");
    expect(explain(p, store, { as: { key: "vendor-guest" }, op: "r", resource: { kind: "stream", id: "relaycast:channel/collab-x" } }, later).reason).toBe("key_expired");
  });

  it("an owner is only matched for a registered agent", () => {
    const p = examplePolicy();
    const store = new Store(":memory:");
    const a = store.createAgent("local-a", 11, "local", undefined);
    store.putStream({ id: "relaycast:channel/mine", owner: a.id, gid: 11, mode: "600", classify: false, acl: [] });
    const q = (as: object) => explain(p, store, { as: as as never, op: "w", resource: { kind: "stream", id: "relaycast:channel/mine" } }, NOW);
    expect(q({ agent: "local-a" }).decision).toBe("allow");
    expect(q({ key: "local" }).decision).toBe("deny");
  });
});

describe("examples/policy.double-pit.json", () => {
  const raw = () =>
    JSON.parse(readFileSync(new URL("../examples/policy.double-pit.json", import.meta.url), "utf8").replace(/<sha256[^>]*>/g, "0".repeat(64)));
  const cases = () => JSON.parse(readFileSync(new URL("../examples/cases.double-pit.json", import.meta.url), "utf8")).cases;

  it("passes every case in examples/cases.double-pit.json", () => {
    const results = runCases(parsePolicy(raw()), undefined, cases(), NOW);
    expect(results.filter((r) => !r.pass).map((r) => r.case.note)).toEqual([]);
    expect(results.length).toBeGreaterThan(30);
  });

  it("leaves other at 0 on every default", () => {
    const p = parsePolicy(raw());
    expect([...p.streamDefaults, ...p.sessionDefaults].map((d) => d.mode[2])).toEqual(
      [...p.streamDefaults, ...p.sessionDefaults].map(() => "0"),
    );
  });
});

describe("explain for sessions", () => {
  it("uses a recorded session's owner and group, or a hypothetical first uploader's group", () => {
    const p = examplePolicy();
    const store = new Store(":memory:");
    const a = store.createAgent("local-a", 11, "local", undefined);
    store.claimSessions(["s1"], a.id, 11);
    const q = (as: object, op: "r" | "w", resource: object) => explain(p, store, { as: as as never, op, resource: resource as never }, NOW);
    expect(q({ key: "pit" }, "r", { kind: "session", id: "s1" }).decision).toBe("allow");
    expect(q({ key: "pit" }, "w", { kind: "session", id: "s1" }).decision).toBe("deny");
    expect(q({ key: "local" }, "r", { kind: "session", id: "s-unknown" }).reason).toBe("unknown_session");
    expect(q({ key: "pit" }, "r", { kind: "session", id: "s-new", gid: 22 }).decision).toBe("allow");
  });
});

describe("POST /admin/v1/explain", () => {
  function harness(adminToken?: string) {
    const policy = examplePolicy();
    const app = createApp({ store: new Store(":memory:"), policy: () => policy, classifier: () => new RuleClassifier([]), adminToken, now: () => NOW });
    return (body: unknown, token?: string) =>
      app.request("/admin/v1/explain", {
        method: "POST",
        headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(body),
      });
  }
  const query = { as: { key: "vendor-guest" }, op: "w", resource: { kind: "stream", id: "relaycast:inbox/pit-a" } };

  it("is off without an admin token and refuses rg_ tokens", async () => {
    expect((await harness()(query, ADMIN)).status).toBe(404);
    expect((await harness(ADMIN)(query, "rg_whatever")).status).toBe(401);
  });

  it("explains against the live policy", async () => {
    const res = await harness(ADMIN)(query, ADMIN);
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ draft: false, decision: "deny", reason: "ceiling:44->22:prefix" });
  });

  it("tests a draft policy without applying it, and rejects an invalid draft", async () => {
    const call = harness(ADMIN);
    const draft = examplePolicyRaw();
    draft.ceilings = []; // a drafted policy that forgot the ceiling
    draft.streamDefaults.push({ prefix: "relaycast:inbox/pit-open-", gid: 22, mode: "662" });
    const cases = [
      { note: "guest never reaches the pit", as: { key: "vendor-guest" }, op: "w", resource: { kind: "stream", id: "relaycast:inbox/pit-open-1" }, expect: "deny" },
    ];
    const res = await (await call({ policy: draft, cases }, ADMIN)).json();
    expect(res).toMatchObject({ draft: true, passed: 0, failed: 1 });
    // The live policy is untouched.
    expect((await (await call(query, ADMIN)).json()).decision).toBe("deny");

    draft.streamDefaults.push({ prefix: "x:", gid: 99, mode: "660" });
    const bad = await call({ policy: draft, ...query }, ADMIN);
    expect(bad.status).toBe(400);
    expect((await bad.json()).error).toBe("relaygate_bad_policy");
  });
});

describe("relaygate-explain CLI", { timeout: 120_000 }, () => {
  const dir = mkdtempSync(join(tmpdir(), "rg-explain-"));
  const policyPath = join(dir, "policy.json");
  writeFileSync(policyPath, JSON.stringify(examplePolicyRaw()));
  const run = (...args: string[]) => {
    try {
      return { code: 0, out: execFileSync(process.execPath, ["--import", "tsx", "src/explain-cli.ts", "--policy", policyPath, ...args], { encoding: "utf8" }) };
    } catch (error) {
      const e = error as { status: number; stdout: string };
      return { code: e.status, out: e.stdout };
    }
  };

  it("exits 0 on allow and 1 on deny, with the reason", () => {
    expect(run("--as", "key:local", "--op", "w", "--stream", "relaycast:inbox/pit-a").code).toBe(0);
    const denied = run("--as", "key:vendor-guest", "--op", "r", "--stream", "relaycast:inbox/pit-a");
    expect(denied.code).toBe(1);
    expect(denied.out).toMatch(/ceiling:44->22/);
  });

  it("runs a cases file and fails on a mismatch", () => {
    const cases = join(dir, "cases.json");
    writeFileSync(cases, JSON.stringify([{ as: { gid: 44 }, op: "r", resource: { kind: "stream", id: "relaycast:channel/general" }, expect: "allow" }]));
    const res = run("--cases", cases);
    expect(res.code).toBe(1);
    expect(res.out).toMatch(/0 passed, 1 failed/);
  });
});

