import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { afterEach, describe, expect, it } from "vitest";
import { WebSocket, WebSocketServer } from "ws";
import { createApp, type Deps } from "../src/app.js";
import { ChainClassifier, RuleClassifier, type Classifier } from "../src/classifier.js";
import { parsePolicy, type Policy } from "../src/policy.js";
import { NodeSockets } from "../src/realtime.js";
import { RelaycastUpstream } from "../src/relaycast.js";
import { SecretBox, sha256, Store } from "../src/store.js";
import { fakeRelaycast, WORKSPACE_KEY } from "./fakes/relaycast.js";

const KEYS = { local: "enroll-local-0000000000000000", pit: "enroll-pit-00000000000000000000", guest: "enroll-guest-0000000000000000000" };

function policy(): Policy {
  return parsePolicy({
    groups: [
      { gid: 11, name: "local" },
      { gid: 22, name: "pit" },
      { gid: 44, name: "guest" },
    ],
    enrollmentKeys: [
      { id: "local", gid: 11, sha256: sha256(KEYS.local), namePrefix: "local-" },
      { id: "pit", gid: 22, sha256: sha256(KEYS.pit), namePrefix: "pit-" },
      { id: "vendor", gid: 44, sha256: sha256(KEYS.guest), namePrefix: "guest-", guest: true, expiresAt: "2099-01-01T00:00:00Z" },
    ],
    streamDefaults: [
      { prefix: "relaycast:channel/", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }] },
      { prefix: "relaycast:channel/pit-", gid: 22, mode: "660", acl: [{ gid: 11, perm: "w" }] },
      { prefix: "relaycast:channel/collab-", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }, { gid: 44, perm: "rw" }] },
      { prefix: "relaycast:inbox/local-", gid: 11, mode: "660", acl: [{ gid: 22, perm: "r" }] },
      { prefix: "relaycast:inbox/pit-", gid: 22, mode: "660", acl: [{ gid: 11, perm: "w" }] },
      { prefix: "relaycast:inbox/guest-", gid: 44, mode: "660", acl: [{ gid: 11, perm: "w" }] },
    ],
    ceilings: [{ gid: 44, never: [22] }],
    classifier: { rules: [{ id: "ssn", pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b" }] },
  });
}

function harness(model: Classifier = { classify: async () => ({ decision: "allow", reason: "ok" }) }, url = "http://relaycast.test") {
  const store = new Store(":memory:");
  const upstreamFake = fakeRelaycast();
  const pol = policy();
  const relaycast = new RelaycastUpstream({ url, workspaceKey: WORKSPACE_KEY, box: new SecretBox("s".repeat(32)), fetch: upstreamFake.fetchFn }, store);
  const classifier = new ChainClassifier([new RuleClassifier(pol.classifier.rules), model]);
  const deps: Deps = { store, policy: () => pol, classifier: () => classifier, relaycast };
  const app = createApp(deps);
  const call = async (method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}) => {
    const res = await app.request(path, {
      method,
      headers: { "content-type": "application/json", authorization: `Bearer ${token}`, ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  const register = async (key: string, name: string, recovery?: string) => (await call("POST", "/v1/register", key, { name, recovery })).body;
  const token = async (key: string, name: string) => String((await register(key, name)).token);
  return { store, deps, app, call, register, token, up: upstreamFake, relaycast };
}

describe("Relaycast proxy: identity and provenance", () => {
  it("registers the agent upstream on first use and never hands out the at_live_ token", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const res = await h.call("GET", "/v1/agent", local);
    expect(res.status).toBe(200);
    expect(res.body.data.name).toBe("local-a");
    expect(JSON.stringify(res.body)).not.toContain("at_live_");
    const register = h.up.calls.find((c) => c.method === "POST" && c.path === "/v1/agents");
    expect(register?.auth).toBe(`Bearer ${WORKSPACE_KEY}`);
    expect(register?.body).toMatchObject({ name: "local-a", auto_join_general: false });
    // Sealed at rest.
    expect(JSON.stringify(h.store.upstreamAgent(h.store.agentByName("local-a")!.id))).not.toContain("at_live_");
  });

  it("stamps verified provenance, strips forged provenance and `from`, and passes data and Idempotency-Key through", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const res = await h.call(
      "POST",
      "/v1/channels/general/messages",
      local,
      { text: "hello", from: "pit-x", data: { type: "slack.message", relaygate: { agent: "pit-x", groups: ["pit"] } } },
      { "idempotency-key": "idem-1" },
    );
    expect(res.status).toBe(201);
    const sent = h.up.calls.at(-1)!;
    expect(sent.body).toEqual({ text: "hello", data: { type: "slack.message", relaygate: { agent: "local-a", groups: ["local"] } } });
    expect(sent.headers.get("idempotency-key")).toBe("idem-1");
    expect(res.body.data.id).toMatch(/^m\d+$/);
  });

  it("marks a guest's messages guest: true", async () => {
    const h = harness();
    const guest = await h.token(KEYS.guest, "guest-a");
    expect((await h.call("POST", "/v1/channels/collab-design/messages", guest, { text: "proposal" })).status).toBe(201);
    expect((h.up.calls.at(-1)!.body as any).data.relaygate).toEqual({ agent: "guest-a", groups: ["guest"], guest: true });
  });

  it("recovers the upstream token with a takeover when Relaycast stops accepting it", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.call("GET", "/v1/agent", local);
    h.up.revokeUpstreamTokens();
    expect((await h.call("GET", "/v1/agent", local)).status).toBe(200);
    expect(h.up.calls.some((c) => c.path === "/v1/agents/local-a/takeover")).toBe(true);
  });
});

describe("Relaycast proxy: review regressions", () => {
  it("an agent exists upstream from registration, so others can list and DM it before it calls anything", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.token(KEYS.pit, "pit-a");
    expect(h.up.agents.has("pit-a")).toBe(true);
    expect((await h.call("GET", "/v1/agents", local)).body.data.map((a: any) => a.name)).toContain("pit-a");
  });

  it("a DM to a relaygate agent not yet upstream enrolls it first", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.token(KEYS.pit, "pit-a");
    h.up.agents.delete("pit-a");
    // A pre-fix agent: not upstream, no stored credential.
    (h.store as any).db.prepare("DELETE FROM upstream_agents WHERE agent_id = ?").run(h.store.agentByName("pit-a")!.id);
    expect((await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "hi" })).status).toBe(201);
    expect(h.up.agents.has("pit-a")).toBe(true);
  });

  it("fails closed when a message's channel can't be resolved", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const posted = await h.call("POST", "/v1/channels/pit-ops/messages", local, { text: "please review" });
    h.up.setChannelsDown(true);
    expect((await h.call("GET", `/v1/messages/${posted.body.data.id}/replies`, local)).status).not.toBe(200);
  });

  it("uses a renamed channel's current name", async () => {
    const h = harness();
    const pit = await h.token(KEYS.pit, "pit-a");
    const local = await h.token(KEYS.local, "local-a");
    const posted = await h.call("POST", "/v1/channels/general/messages", local, { text: "hello" });
    expect((await h.call("GET", `/v1/messages/${posted.body.data.id}`, pit)).status).toBe(200);
    h.up.channels.find((c) => c.name === "general")!.name = "pit-renamed";
    // Now a pit channel: the local author may not read it back.
    expect((await h.call("GET", `/v1/messages/${posted.body.data.id}`, local)).status).toBe(403);
  });

  it("a DM read by id also needs read on the caller's own inbox", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const pit = await h.token(KEYS.pit, "pit-a");
    const dm = await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "hi" });
    const id = dm.body.data.message.id;
    expect((await h.call("GET", `/v1/messages/${id}`, pit)).status).toBe(200);
    (h.deps.policy() as any).streamOverrides.push({ id: "relaycast:inbox/pit-a", gid: 22, mode: "000", classify: false, acl: [] });
    expect((await h.call("GET", `/v1/messages/${id}`, pit)).status).toBe(403);
    expect((await h.call("GET", "/v1/dm/conversations", pit)).body.data).toEqual([]);
    expect((await h.call("GET", "/v1/inbox", pit)).body.data.unread_dms).toEqual([]);
  });

  it("never forwards `from` on a DM", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.token(KEYS.pit, "pit-a");
    await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "hi", from: "pit-b" });
    expect(h.up.calls.at(-1)!.body).not.toHaveProperty("from");
  });

  it("opens a listed DM conversation whatever characters its id has", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.token(KEYS.pit, "pit-a");
    const dm = await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "hi" });
    expect((await h.call("GET", `/v1/dm/${encodeURIComponent(dm.body.data.conversation_id)}/messages`, local)).status).toBe(200);
  });

  it("concurrent 401s rotate the upstream token once and every request succeeds", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.call("GET", "/v1/agent", local);
    h.up.revokeUpstreamTokens();
    const results = await Promise.all([1, 2, 3, 4].map(() => h.call("GET", "/v1/agent", local)));
    expect(results.map((r) => r.status)).toEqual([200, 200, 200, 200]);
    expect(h.up.calls.filter((c) => c.path.endsWith("/takeover")).length).toBe(1);
  });

  it("takes the identity over when the stored token was sealed with another secret", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    await h.call("GET", "/v1/agent", local);
    const agent = h.store.agentByName("local-a")!;
    h.store.putUpstreamAgent(agent.id, "up_local-a", new SecretBox("another-secret-entirely-000000000").seal("at_live_x"));
    expect((await h.call("GET", "/v1/agent", local)).status).toBe(200);
    expect(h.up.calls.some((c) => c.path.endsWith("/takeover"))).toBe(true);
  });

  it("keeps only a few node tokens per rg_ token", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const tokens: string[] = [];
    for (let i = 0; i < 8; i++) tokens.push((await h.call("POST", "/v1/agent/node-token", local, {})).body.data.token);
    expect(h.store.nodeToken(tokens[0]!)).toBeUndefined();
    expect(h.store.nodeToken(tokens[7]!)).toBeDefined();
  });
});

describe("Relaycast proxy: the pit rules", () => {
  it("refuses a pit agent writing outside the pit before anything reaches Relaycast", async () => {
    const h = harness();
    const pit = await h.token(KEYS.pit, "pit-a");
    const before = h.up.calls.length;
    const res = await h.call("POST", "/v1/channels/general/messages", pit, { text: "x" });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatchObject({ code: "relaygate_denied" });
    expect(h.up.calls.length).toBe(before);
  });

  it("classifies a cross-group write and refuses on content", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    expect((await h.call("POST", "/v1/channels/pit-ops/messages", local, { text: "ssn 123-45-6789" })).body.error.code).toBe("relaygate_classified");
    expect((await h.call("POST", "/v1/channels/pit-ops/messages", local, { text: "please review" })).status).toBe(201);
  });

  it("checks channel reads itself, including GET /messages/:id", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const pit = await h.token(KEYS.pit, "pit-a");
    const posted = await h.call("POST", "/v1/channels/pit-ops/messages", pit, { text: "patient summary" });
    const id = posted.body.data.id;
    expect((await h.call("GET", "/v1/channels/pit-ops/messages", local)).status).toBe(403);
    expect((await h.call("GET", `/v1/messages/${id}`, local)).status).toBe(403);
    expect((await h.call("GET", `/v1/messages/${id}/replies`, local)).status).toBe(403);
    expect((await h.call("GET", `/v1/messages/${id}`, pit)).status).toBe(200);
    // pit may read local channels but not reply into them
    const general = await h.call("POST", "/v1/channels/general/messages", local, { text: "standup" });
    expect((await h.call("GET", `/v1/messages/${general.body.data.id}`, pit)).status).toBe(200);
    expect((await h.call("POST", `/v1/messages/${general.body.data.id}/replies`, pit, { text: "x" })).status).toBe(403);
  });

  it("DMs follow the recipient's inbox, and a DM is readable by id only by its participants", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const pit = await h.token(KEYS.pit, "pit-a");
    const guest = await h.token(KEYS.guest, "guest-a");
    const dm = await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "can you review?" });
    expect(dm.status).toBe(201);
    expect((await h.call("POST", "/v1/dm", pit, { to: "local-a", text: "sure" })).status).toBe(403);
    const id = dm.body.data.message.id;
    expect((await h.call("GET", `/v1/messages/${id}`, pit)).status).toBe(200);
    expect((await h.call("GET", `/v1/messages/${id}`, local)).status).toBe(200);
    expect((await h.call("GET", `/v1/messages/${id}`, guest)).status).toBe(403);
    // Writes into a DM thread aren't modelled.
    expect((await h.call("POST", `/v1/messages/${id}/replies`, pit, { text: "x" })).status).toBe(403);
  });

  it("filters search, channel lists, the inbox and the agent list", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const pit = await h.token(KEYS.pit, "pit-a");
    const guest = await h.token(KEYS.guest, "guest-a");
    await h.call("POST", "/v1/channels/pit-ops/messages", pit, { text: "pit secret" });
    await h.call("POST", "/v1/channels/general/messages", local, { text: "general hello" });
    await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "dm to pit" });

    const search = (await h.call("GET", "/v1/search?q=x", local)).body.data.map((x: any) => x.text);
    expect(search.sort()).toEqual(["dm to pit", "general hello"]);
    const guestSearch = (await h.call("GET", "/v1/search?q=x", guest)).body.data;
    expect(guestSearch).toEqual([]);

    expect((await h.call("GET", "/v1/channels", guest)).body.data.map((c: any) => c.name)).toEqual(["collab-design"]);
    expect((await h.call("GET", "/v1/channels", pit)).body.data.map((c: any) => c.name)).toEqual(["general", "collab-design", "pit-ops"]);

    const inbox = (await h.call("GET", "/v1/inbox", local)).body.data;
    expect(inbox.unread_channels.map((c: any) => c.channel_name)).toEqual(["general", "collab-design"]);
    expect(inbox.mentions).toEqual([]);

    expect((await h.call("GET", "/v1/agents", guest)).body.data.map((a: any) => a.name)).toEqual(["guest-a"]);
    expect((await h.call("GET", "/v1/agents", local)).body.data.map((a: any) => a.name).sort()).toEqual(["guest-a", "local-a", "pit-a"]);
    expect((await h.call("GET", "/v1/agents/pit-a", guest)).status).toBe(404);
  });

  it("lists only 1:1 DM conversations", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const pit = await h.token(KEYS.pit, "pit-a");
    await h.call("POST", "/v1/dm", local, { to: "pit-a", text: "hi" });
    // Both participants see the conversation; the group DM is dropped; a non-participant sees nothing.
    expect((await h.call("GET", "/v1/dm/conversations", local)).body.data.map((c: any) => c.type)).toEqual(["1:1"]);
    expect((await h.call("GET", "/v1/dm/conversations", pit)).body.data.map((c: any) => c.type)).toEqual(["1:1"]);
    expect((await h.call("GET", "/v1/dm/conversations", await h.token(KEYS.pit, "pit-b"))).body.data).toEqual([]);
  });

  it("refuses every route it doesn't proxy, without calling Relaycast", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const before = h.up.calls.length;
    for (const [method, path] of [
      ["POST", "/v1/dm/group"],
      ["DELETE", "/v1/channels/general"],
      ["POST", "/v1/agents/spawn"],
      ["GET", "/v1/workspace"],
      ["GET", "/v1/channels/dm-abc/messages"],
      ["POST", "/v1/files/upload"],
    ] as const) {
      const res = await h.call(method, path, local, method === "GET" || method === "DELETE" ? undefined : {});
      expect(res.status, path).toBe(404);
      expect(res.body).toMatchObject({ ok: false, error: { code: "relaygate_route_not_proxied" } });
    }
    expect(h.up.calls.length).toBe(before);
  });
});

describe("Relaycast proxy: realtime", { timeout: 30_000 }, () => {
  const cleanups: Array<() => void> = [];
  afterEach(() => {
    for (const fn of cleanups.splice(0)) fn();
  });

  async function realtime() {
    // A fake upstream node socket: records what it receives and lets the test push frames.
    const wss = new WebSocketServer({ port: 0 });
    cleanups.push(() => wss.close());
    const upstreamPort = (wss.address() as AddressInfo).port;
    const received: any[] = [];
    let upstreamSocket: WebSocket | undefined;
    let upstreamUrl = "";
    const connected = new Promise<void>((resolve) =>
      wss.on("connection", (ws, req) => {
        upstreamSocket = ws;
        upstreamUrl = req.url ?? "";
        ws.on("message", (d) => received.push(JSON.parse(d.toString())));
        resolve();
      }),
    );
    const h = harness(undefined, `http://127.0.0.1:${upstreamPort}`);
    const sockets = new NodeSockets(h.deps, h.relaycast, 60_000);
    h.deps.onTokensRevoked = () => sockets.revalidate();
    const server = serve({ fetch: h.app.fetch, port: 0 }) as unknown as Server;
    await new Promise<void>((r) => (server.listening ? r() : server.once("listening", () => r())));
    sockets.attach(server);
    cleanups.push(() => {
      sockets.close();
      server.close();
    });
    const port = (server.address() as AddressInfo).port;
    return { h, sockets, port, received, connected, upstream: () => upstreamSocket!, upstreamUrl: () => upstreamUrl };
  }

  const waitFor = async (cond: () => boolean, ms = 3000) => {
    const start = Date.now();
    while (!cond()) {
      if (Date.now() - start > ms) throw new Error("timed out");
      await new Promise((r) => setTimeout(r, 10));
    }
  };

  it("mints an rgn_ token, filters frames both ways, and closes when the rg_ token is revoked", async () => {
    const rt = await realtime();
    const proof = "recovery-proof-0123456789";
    const local = String((await rt.h.register(KEYS.local, "local-a", proof)).token);
    const nt = await rt.h.call("POST", "/v1/agent/node-token", local, {});
    expect(nt.status).toBe(200);
    expect(nt.body.data.token).toMatch(/^rgn_/);
    expect(JSON.stringify(nt.body)).not.toContain("nt_live_");

    // A malformed request target is refused without taking the gateway down.
    const { connect } = await import("node:net");
    await new Promise<void>((resolve) => {
      const sock = connect(rt.port, "127.0.0.1", () => sock.write("GET //[ HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"));
      sock.on("data", () => sock.destroy());
      sock.on("close", () => resolve());
    });
    expect((await rt.h.call("GET", "/v1/whoami", local)).status).toBe(200);

    // A bad token never gets a socket.
    const bad = new WebSocket(`ws://127.0.0.1:${rt.port}/v1/node/ws?token=rgn_nope`);
    const badResult = await new Promise((r) => bad.on("error", () => r("error")).on("open", () => r("open")));
    expect(badResult).toBe("error");

    const client = new WebSocket(`ws://127.0.0.1:${rt.port}/v1/node/ws?token=${nt.body.data.token}`);
    const got: any[] = [];
    client.on("message", (d) => got.push(JSON.parse(d.toString())));
    const closed = new Promise<number>((r) => client.on("close", (code) => r(code)));
    await new Promise((r) => client.on("open", r));
    await rt.connected;
    expect(rt.upstreamUrl()).toMatch(/token=nt_live_/);

    client.send(
      JSON.stringify({
        v: 1,
        type: "node.register",
        name: "x",
        node_id: "someone-elses-node",
        capabilities: [{ name: "spawn" }],
        max_agents: 5,
        machine_id: "mach-1",
        origin_surface: "desktop",
        provider: { name: "relay-node", instance_id: "inst-1" },
      }),
    );
    client.send(JSON.stringify({ v: 1, id: "r1", type: "agent.register", name: "pit-sneaky" }));
    client.send(JSON.stringify({ v: 1, type: "delivery.ack", agent: "pit-a", up_to_seq: 9 }));
    client.send(JSON.stringify({ v: 1, type: "delivery.ack", agent: "local-a", up_to_seq: 3 }));
    await waitFor(() => rt.received.length >= 2 && got.some((f) => f.id === "r1"));
    expect(rt.received).toEqual([
      // Everything but node_id and capabilities passes through (machine_id, origin_surface, provider, ...).
      { v: 1, type: "node.register", name: "x", node_id: "node_local-a", capabilities: [], max_agents: 5, machine_id: "mach-1", origin_surface: "desktop", provider: { name: "relay-node", instance_id: "inst-1" } },
      { v: 1, type: "delivery.ack", agent: "local-a", up_to_seq: 3 },
    ]);
    expect(got.find((f) => f.id === "r1")).toMatchObject({ type: "error", code: "relaygate_denied" });

    const deliver = (seq: number, type: string, data: object, agent = "local-a") =>
      rt.upstream().send(JSON.stringify({ v: 1, type: "deliver", delivery_id: `d${seq}`, agent_id: "x", agent, msg_id: `m${seq}`, seq, mode: "wait", payload: { type, data } }));
    deliver(1, "message.created", { channel_name: "pit-ops", text: "pit secret" });
    deliver(2, "message.created", { channel_name: "general", text: "hello" });
    deliver(3, "dm.received", { from_name: "guest-a", text: "hi" });
    deliver(4, "message.created", { channel_name: "general", text: "for someone else" }, "local-b");
    deliver(5, "group_dm.received", { text: "group" });
    rt.upstream().send(JSON.stringify({ v: 1, type: "action.invoke", invocation_id: "i1", action: "spawn", input: {} }));
    rt.upstream().send(JSON.stringify({ v: 1, type: "ping" }));
    await waitFor(() => got.some((f) => f.type === "ping"));
    expect(got.filter((f) => f.type === "deliver").map((f) => f.seq)).toEqual([2, 3]);
    expect(got.some((f) => f.type === "action.invoke")).toBe(false);

    // Re-registering with the recovery proof revokes the old rg_ token, which closes the socket at once.
    await rt.h.register(KEYS.local, "local-a", proof);
    expect(await closed).toBe(4401);
    expect(rt.sockets.size).toBe(0);
  });
});

describe("Relaycast proxy: desktop broker routes", () => {
  it("serves the delivery queue filtered by read access, and fails what it withholds upstream", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const pit = await h.token(KEYS.pit, "pit-a");
    await h.call("POST", "/v1/channels/general/messages", pit, { text: "x" }).catch(() => {});
    h.up.deliveries.push(
      { id: "dl1", agent: "local-a", channel_id: "ch_general", message: { text: "general" } },
      { id: "dl2", agent: "local-a", channel_id: "ch_pit", message: { text: "pit secret" } },
      { id: "dl3", agent: "local-a", channel_id: "dmch_local-a~pit-a", message: { text: "a dm" } },
      { id: "dl4", agent: "local-a", channel_id: "ch_unknown", message: { text: "?" } },
    );
    const res = await h.call("GET", "/v1/deliveries?limit=50", local);
    expect(res.status).toBe(200);
    expect(res.body.data.map((d: any) => d.id)).toEqual(["dl1", "dl3"]);
    expect(h.up.failed).toEqual([
      { id: "dl2", body: { error: "relaygate_denied", retryable: false } },
      { id: "dl4", body: { error: "relaygate_denied", retryable: false } },
    ]);
    expect((await h.call("POST", "/v1/deliveries/dl1/ack", local, {})).status).toBe(200);
    expect(h.up.calls.at(-1)).toMatchObject({ method: "POST", path: "/v1/deliveries/dl1/ack" });
  });

  it("lets an agent update and remove only itself; removal ends its tokens", async () => {
    const h = harness();
    const local = await h.token(KEYS.local, "local-a");
    const patched = await h.call("PATCH", "/v1/agent", local, { status: "online", metadata: { cwd: "/x", relaygate: { forged: true } }, name: "pit-a" });
    expect(patched.status).toBe(200);
    expect(h.up.calls.at(-1)).toMatchObject({ method: "PATCH", path: "/v1/agents/local-a", body: { status: "online", metadata: { cwd: "/x" } } });
    expect((await h.call("DELETE", "/v1/agent", local)).status).toBe(200);
    expect(h.up.calls.at(-1)).toMatchObject({ method: "DELETE", path: "/v1/agents/local-a" });
    expect((await h.call("GET", "/v1/agent", local)).status).toBe(401);
  });
});

