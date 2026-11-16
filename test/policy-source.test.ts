import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { classifierFromPolicy } from "../src/classifier.js";
import { policyVersion } from "../src/policy.js";
import { ControlPolicySource, signPolicyBody } from "../src/policy-source.js";
import { sha256, Store } from "../src/store.js";

const SECRET = "policy-secret-0123456789abcdef0123456789";
const ADMIN = "admin-token-0123456789abcdef";
const KEY = "enroll-local-0000000000000000";

const policyBody = (extraGroup?: string) => ({
  groups: [{ gid: 11, name: "local" }, ...(extraGroup ? [{ gid: 12, name: extraGroup }] : [])],
  enrollmentKeys: [{ id: "local", gid: 11, sha256: sha256(KEY) }],
  streamDefaults: [{ prefix: "relaycast:channel/", gid: 11, mode: "660" }],
});

/** A stand-in relay-control policy route: serves whatever answer is set, signed unless told otherwise. */
function fakeControl() {
  const state: { status: number; body: string; signature?: string; down: boolean; seen: Array<{ auth: string | null; inm: string | null }> } = {
    status: 200,
    body: "",
    down: false,
    seen: [],
  };
  const serve = (version: number, policy: unknown, opts: { sign?: string } = {}) => {
    state.status = 200;
    state.body = JSON.stringify({ version, updatedAt: "2026-11-16T00:00:00Z", policy });
    state.signature = opts.sign ?? signPolicyBody(SECRET, state.body);
  };
  const fetchFn = (async (_url: RequestInfo | URL, init?: RequestInit) => {
    const h = new Headers(init?.headers);
    state.seen.push({ auth: h.get("authorization"), inm: h.get("if-none-match") });
    if (state.down) throw new TypeError("fetch failed");
    const version = state.body ? JSON.parse(state.body).version : undefined;
    if (version !== undefined && h.get("if-none-match") === `"${version}"`) return new Response(null, { status: 304 });
    return new Response(state.body, { status: state.status, headers: state.signature ? { "x-relaycontrol-signature": state.signature } : {} });
  }) as typeof fetch;
  return { state, serve, fetchFn };
}

function gate(store: Store, source: ControlPolicySource) {
  const app = createApp({
    store,
    policy: () => source.current(),
    classifier: () => classifierFromPolicy(source.current()),
    policyStatus: () => source.status(),
    adminToken: ADMIN,
  });
  const call = async (method: string, path: string, token?: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  return call;
}

describe("policy from relay-control", () => {
  it("fails closed until the first good pull, then enforces it", async () => {
    const store = new Store(":memory:");
    const control = fakeControl();
    control.state.down = true;
    const source = new ControlPolicySource({ url: "http://control.test/internal/v1/relaygate/policy", secret: SECRET, fetch: control.fetchFn }, store);
    const call = gate(store, source);
    await source.refresh();
    expect((await call("GET", "/healthz")).status).toBe(200);
    expect((await call("GET", "/readyz")).status).toBe(503);
    expect(await call("POST", "/v1/register", KEY, { name: "a1" })).toMatchObject({ status: 503, body: { error: "relaygate_unavailable" } });
    // Operators still see why.
    expect((await call("GET", "/admin/v1/policy/status", ADMIN)).body).toMatchObject({ source: "control", lastError: "policy fetch failed: TypeError" });
    expect((await call("GET", "/admin/v1/policy/status")).status).toBe(401);

    control.state.down = false;
    control.serve(1, policyBody());
    expect(await source.refresh()).toBe(true);
    expect(control.state.seen.at(-1)!.auth).toBe(`Bearer ${SECRET}`);
    expect((await call("POST", "/v1/register", KEY, { name: "a1" })).status).toBe(200);
    const status = (await call("GET", "/admin/v1/policy/status", ADMIN)).body;
    expect(status).toMatchObject({ source: "control", version: 1 });
    expect(status.hash).toMatch(/^c1-[0-9a-f]{12}$/);
    expect(status.lastError).toBeUndefined();
    // Audit rows record relay-control's version.
    expect(policyVersion(source.current())).toBe(status.hash);
    // Unchanged: a conditional request, answered 304.
    expect(await source.refresh()).toBe(false);
    expect(control.state.seen.at(-1)!.inm).toBe('"1"');
  });

  it("keeps the policy in force when a new one doesn't verify, doesn't parse, or is older", async () => {
    const store = new Store(":memory:");
    const control = fakeControl();
    const source = new ControlPolicySource({ url: "http://control.test/p", secret: SECRET, fetch: control.fetchFn }, store);
    control.serve(5, policyBody());
    await source.refresh();
    const good = source.current();

    control.serve(6, policyBody("extra"), { sign: signPolicyBody("someone-else-0123456789abcdef0123", "x") });
    expect(await source.refresh()).toBe(false);
    expect(source.current()).toBe(good);
    expect(source.status().lastRejected).toMatchObject({ reason: "signature does not verify" });

    control.serve(6, { groups: [] });
    expect(await source.refresh()).toBe(false);
    expect(source.current()).toBe(good);
    expect(source.status().lastRejected).toMatchObject({ version: 6 });
    expect(source.status().lastRejected!.reason).toMatch(/^policy does not parse/);

    control.serve(4, policyBody("older"));
    expect(await source.refresh()).toBe(false);
    expect(source.status().lastRejected).toMatchObject({ version: 4, reason: "version 4 is older than 5 in force" });

    control.state.status = 500;
    expect(await source.refresh()).toBe(false);
    expect(source.status().lastError).toBe("policy fetch answered 500");

    // Headers, then a body that never completes.
    const broken = new ControlPolicySource(
      { url: "http://control.test/p", secret: SECRET, fetch: (async () => new Response(new ReadableStream({ start: (c) => c.error(new Error("reset")) }), { status: 200 })) as typeof fetch },
      new Store(":memory:"),
    );
    expect(await broken.refresh()).toBe(false);
    expect(broken.status().lastError).toMatch(/^policy body read failed/);

    control.serve(7, policyBody("extra"));
    expect(await source.refresh()).toBe(true);
    expect(source.current().groups.map((g) => g.name)).toEqual(["local", "extra"]);
  });

  it("restarts from the cached copy while relay-control is down, and never from a tampered one", async () => {
    const dir = await import("node:fs/promises").then((fs) => fs.mkdtemp("/tmp/rg-policy-"));
    const path = `${dir}/rg.db`;
    const control = fakeControl();
    control.serve(3, policyBody("cached"));
    const first = new ControlPolicySource({ url: "http://control.test/p", secret: SECRET, fetch: control.fetchFn }, new Store(path));
    await first.refresh();

    control.state.down = true;
    const store = new Store(path);
    const restarted = new ControlPolicySource({ url: "http://control.test/p", secret: SECRET, fetch: control.fetchFn }, store);
    expect(restarted.current().groups.map((g) => g.name)).toEqual(["local", "cached"]);
    expect(restarted.status()).toMatchObject({ version: 3 });

    // Someone edits the cached copy: it no longer verifies, so relaygate refuses everything instead.
    const cached = store.cachedPolicy()!;
    store.cachePolicy({ ...cached, body: cached.body.replace('"cached"', '"widened"') });
    const tampered = new ControlPolicySource({ url: "http://control.test/p", secret: SECRET, fetch: control.fetchFn }, new Store(path));
    expect(() => tampered.current()).toThrow();
    expect(tampered.status().lastError).toMatch(/signature does not verify/);
  });
});
