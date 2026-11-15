import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { ChainClassifier, RuleClassifier } from "../src/classifier.js";
import { parsePolicy } from "../src/policy.js";
import { sha256, Store } from "../src/store.js";

const KEYS = { local: "enroll-local-0000000000000000", pit: "enroll-pit-00000000000000000000", guest: "enroll-guest-0000000000000000000" };
const SERVICE = "rth_st_service";

function policy(shared: string[] = [], mistaken: string[] = []) {
  return parsePolicy({
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 44, name: "guest" },
    ],
    enrollmentKeys: [
      { id: "local", gid: 11, sha256: sha256(KEYS.local) },
      { id: "pit", gid: 22, sha256: sha256(KEYS.pit) },
      { id: "vendor", gid: 44, sha256: sha256(KEYS.guest), guest: true, expiresAt: "2099-01-01T00:00:00Z" },
    ],
    sessionDefaults: [
      { gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }] },
      { gid: 22, mode: "660" },
    ],
    sessionOverrides: [
      ...shared.map((id) => ({ id, acl: [{ gid: 44, perm: "r" }] })),
      ...mistaken.map((id) => ({ id, mode: "666", acl: [{ gid: 44, perm: "rw" }] })),
    ],
    ceilings: [{ gid: 44, never: [22] }],
    classifier: { rules: [{ id: "ssn", pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b" }] },
  });
}

function harness(pol = policy()) {
  const calls: Array<{ method: string; path: string; auth: string; body: unknown }> = [];
  const upstream = new Hono();
  upstream.use("*", async (c, next) => {
    const body = c.req.method === "POST" ? await c.req.raw.clone().json() : undefined;
    calls.push({ method: c.req.method, path: c.req.path + new URL(c.req.url).search, auth: c.req.header("authorization") ?? "", body });
    await next();
  });
  upstream.post("/v1/sessions/:id/turns", (c) => c.json({ accepted: 1 }));
  upstream.post("/v1/ingest", (c) => c.json({ received: 1 }));
  upstream.get("/v1/sessions", (c) => c.json({ sessions: [{ sessionId: "s-local" }, { sessionId: "s-pit" }, { sessionId: "s-elsewhere" }], nextCursor: "c2" }));
  upstream.get("/v1/sessions/:id/events", (c) => c.json({ events: [{ sessionId: c.req.param("id") }] }));
  upstream.get("/v1/events", (c) => c.json({ events: [] }));
  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => upstream.fetch(new Request(input, init))) as typeof fetch;

  const store = new Store(":memory:");
  const classifier = new ChainClassifier([new RuleClassifier(pol.classifier.rules)]);
  const app = createApp({ store, policy: () => pol, classifier: () => classifier, sessions: { url: "http://sessions.test", token: SERVICE, fetch: fetchFn } });
  const call = async (method: string, path: string, token: string, body?: unknown) => {
    const res = await app.request(path, {
      method,
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  const token = async (key: string, name: string) => String((await call("POST", "/v1/register", key, { name })).body.token);
  const turns = (tok: string, id: string, content = "worked on it") =>
    call("POST", `/sessions/v1/sessions/${id}/turns`, tok, { sessionOwner: "someone-else", turns: [{ turnIndex: 0, role: "assistant", content, sessionOwner: "forged" }] });
  return { store, call, token, turns, calls };
}

async function world(pol = policy()) {
  const h = harness(pol);
  const local = await h.token(KEYS.local, "local-a");
  const pit = await h.token(KEYS.pit, "pit-a");
  const guest = await h.token(KEYS.guest, "guest-a");
  expect((await h.turns(local, "s-local")).status).toBe(200);
  expect((await h.turns(pit, "s-pit")).status).toBe(200);
  return { ...h, local, pit, guest };
}

describe("Sessions proxy: uploads", () => {
  it("the first uploader owns a session; turns are attributed to it and sent with the service token", async () => {
    const w = await world();
    const sent = w.calls.find((c) => c.path === "/v1/sessions/s-local/turns")!;
    expect(sent.auth).toBe(`Bearer ${SERVICE}`);
    expect(sent.body).toMatchObject({ sessionOwner: "local-a", turns: [{ sessionOwner: "local-a", content: "worked on it" }] });
    expect(w.store.session("s-local")).toMatchObject({ gid: 11 });
  });

  it("pit agents can't write local sessions, and local agents can't write pit sessions", async () => {
    const w = await world();
    const before = w.calls.length;
    expect((await w.turns(w.pit, "s-local")).status).toBe(403);
    expect((await w.turns(w.local, "s-pit")).status).toBe(403);
    expect(w.calls.length).toBe(before);
    // Ownership never moves.
    expect(w.store.session("s-local")?.owner).toBe(w.store.agentByName("local-a")?.id);
  });

  it("a batch is all or nothing, and a refused batch claims no new session", async () => {
    const w = await world();
    const before = w.calls.length;
    const res = await w.call("POST", "/sessions/v1/ingest", w.local, {
      machine: {},
      batchId: "b1",
      records: [
        { v: 1, kind: "turn", source: "cli", sessionId: "s-new", content: "fine" },
        { v: 1, kind: "turn", source: "cli", sessionId: "s-pit", content: "sneak" },
      ],
    });
    expect(res.status).toBe(403);
    expect(w.calls.length).toBe(before);
    expect(w.store.session("s-new")).toBeUndefined();
    expect((await w.call("POST", "/sessions/v1/ingest", w.local, { machine: {}, batchId: "b2", records: [{ v: 1, kind: "turn", source: "cli", sessionId: "s-new", content: "fine" }] })).status).toBe(200);
    expect(w.store.session("s-new")?.gid).toBe(11);
  });
});

describe("Sessions proxy: reads", () => {
  it("pit agents read local sessions; local agents never read pit sessions", async () => {
    const w = await world();
    expect((await w.call("GET", "/sessions/v1/sessions/s-local/events", w.pit)).status).toBe(200);
    expect((await w.call("GET", "/sessions/v1/sessions/s-pit/turns", w.local)).status).toBe(403);
    expect((await w.call("GET", "/sessions/v1/sessions/s-elsewhere/events", w.pit)).status).toBe(403);
  });

  it("a guest reads only the sessions shared with it, and never a pit session even with a mistaken override", async () => {
    const w = await world(policy(["s-local"], ["s-pit"]));
    expect((await w.call("GET", "/sessions/v1/sessions/s-local/events", w.guest)).status).toBe(200);
    expect((await w.turns(w.guest, "s-local")).status).toBe(403);
    expect((await w.call("GET", "/sessions/v1/sessions/s-pit/events", w.guest)).status).toBe(403);
    expect((await w.turns(w.guest, "s-pit")).status).toBe(403);
    // Without the share, the guest sees nothing.
    const plain = await world();
    expect((await plain.call("GET", "/sessions/v1/sessions/s-local/events", plain.guest)).status).toBe(403);
  });

  it("filters lists to readable sessions and keeps the cursor", async () => {
    const w = await world();
    const list = async (tok: string) => (await w.call("GET", "/sessions/v1/sessions?limit=10", tok)).body;
    expect((await list(w.local)).sessions.map((s: any) => s.sessionId)).toEqual(["s-local"]);
    expect((await list(w.pit)).sessions.map((s: any) => s.sessionId)).toEqual(["s-local", "s-pit"]);
    expect((await list(w.guest)).sessions).toEqual([]);
    expect((await list(w.local)).nextCursor).toBe("c2");
    expect(w.calls.at(-1)?.path).toBe("/v1/sessions?limit=10");
  });

  it("GET /events needs exactly one readable session", async () => {
    const w = await world();
    expect((await w.call("GET", "/sessions/v1/events", w.local)).status).toBe(400);
    expect((await w.call("GET", "/sessions/v1/events?session=s-local&session=s-pit", w.local)).status).toBe(400);
    expect((await w.call("GET", "/sessions/v1/events?session=s-pit", w.local)).status).toBe(403);
    expect((await w.call("GET", "/sessions/v1/events?session=s-local", w.local)).status).toBe(200);
  });

  it("refuses unknown routes and unauthenticated calls", async () => {
    const w = await world();
    expect((await w.call("POST", "/sessions/v1/delivery/batches", w.local, {})).body.error.code).toBe("relaygate_route_not_proxied");
    expect((await w.call("GET", "/sessions/v1/sessions", "rg_nope")).status).toBe(401);
  });
});
