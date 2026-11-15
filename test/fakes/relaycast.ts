import { Hono } from "hono";

export const WORKSPACE_KEY = "rk_live_test";

interface Msg {
  id: string;
  channel_id: string;
  agent_name: string;
  text: string;
  metadata: unknown;
}

/** A small in-memory Relaycast with the shapes relaygate relies on (from packages/engine). */
export function fakeRelaycast() {
  const agents = new Map<string, { id: string; token: string }>();
  const channels = [
    { id: "ch_general", name: "general" },
    { id: "ch_collab", name: "collab-design" },
    { id: "ch_pit", name: "pit-ops" },
  ];
  const messages: Msg[] = [];
  const calls: Array<{ method: string; path: string; auth: string; body: unknown; headers: Headers }> = [];
  let seq = 0;
  let revokeAll = false;
  let channelsDown = false;
  const app = new Hono();
  const who = (auth: string) => [...agents.entries()].find(([, a]) => `Bearer ${a.token}` === auth)?.[0];
  const pairOf = (a: string, b: string) => [a, b].sort().join("~");

  app.use("*", async (c, next) => {
    const body = c.req.method === "GET" || c.req.method === "DELETE" ? undefined : await c.req.raw.clone().json().catch(() => undefined);
    calls.push({ method: c.req.method, path: c.req.path, auth: c.req.header("authorization") ?? "", body, headers: c.req.raw.headers });
    const auth = c.req.header("authorization") ?? "";
    if (auth !== `Bearer ${WORKSPACE_KEY}` && (!who(auth) || revokeAll)) return c.json({ ok: false, error: { code: "unauthorized" } }, 401);
    await next();
  });
  app.post("/v1/agents", async (c) => {
    const { name } = await c.req.json();
    if (agents.has(name)) return c.json({ ok: false, error: { code: "agent_already_exists" } }, 409);
    const a = { id: `up_${name}`, token: `at_live_${name}_${++seq}` };
    agents.set(name, a);
    return c.json({ ok: true, data: { id: a.id, name, token: a.token } }, 201);
  });
  app.get("/v1/agents", (c) => c.json({ ok: true, data: [...agents.entries()].map(([name, a]) => ({ id: a.id, name })) }));
  app.get("/v1/agents/:name", (c) => {
    const a = agents.get(c.req.param("name"));
    return a ? c.json({ ok: true, data: { id: a.id, name: c.req.param("name") } }) : c.json({ ok: false }, 404);
  });
  app.post("/v1/agents/:name/takeover", (c) => {
    const a = agents.get(c.req.param("name"))!;
    a.token = `at_live_${c.req.param("name")}_${++seq}`;
    revokeAll = false;
    return c.json({ ok: true, data: { agent_id: a.id, token: a.token } });
  });
  app.get("/v1/agent", (c) => c.json({ ok: true, data: { name: who(c.req.header("authorization")!) } }));
  app.get("/v1/channels", (c) => (channelsDown ? c.json({ ok: false, error: { code: "boom" } }, 500) : c.json({ ok: true, data: channels })));
  app.get("/v1/dm/:cid/messages", (c) => {
    const me = who(c.req.header("authorization")!)!;
    const pair = c.req.param("cid").slice(3);
    if (!pair.split("~").includes(me)) return c.json({ ok: false, error: { code: "forbidden" } }, 403);
    return c.json({ ok: true, data: messages.filter((m) => m.channel_id === `dmch_${pair}`) });
  });
  app.post("/v1/channels", async (c) => {
    const { name } = await c.req.json();
    if (channels.some((x) => x.name === name)) return c.json({ ok: false, error: { code: "channel_already_exists" } }, 409);
    const ch = { id: `ch_${++seq}`, name };
    channels.push(ch);
    return c.json({ ok: true, data: ch }, 201);
  });
  app.get("/v1/channels/:name", (c) => {
    const ch = channels.find((x) => x.name === c.req.param("name"));
    return ch ? c.json({ ok: true, data: ch }) : c.json({ ok: false, error: { code: "channel_not_found" } }, 404);
  });
  app.post("/v1/channels/:name/join", (c) => c.json({ ok: true, data: { joined: true } }));
  app.post("/v1/channels/:name/messages", async (c) => {
    const ch = channels.find((x) => x.name === c.req.param("name"));
    if (!ch) return c.json({ ok: false, error: { code: "channel_not_found" } }, 404);
    const body = await c.req.json();
    const m = { id: `m${++seq}`, channel_id: ch.id, agent_name: who(c.req.header("authorization")!)!, text: body.text, metadata: body.data };
    messages.push(m);
    return c.json({ ok: true, data: m }, 201);
  });
  app.get("/v1/channels/:name/messages", (c) => {
    const ch = channels.find((x) => x.name === c.req.param("name"))!;
    return c.json({ ok: true, data: messages.filter((m) => m.channel_id === ch.id) });
  });
  app.get("/v1/messages/:id", (c) => {
    const m = messages.find((x) => x.id === c.req.param("id"));
    return m ? c.json({ ok: true, data: m }) : c.json({ ok: false, error: { code: "not_found" } }, 404);
  });
  app.post("/v1/messages/:id/replies", async (c) => {
    const parent = messages.find((x) => x.id === c.req.param("id"))!;
    const body = await c.req.json();
    const m = { id: `m${++seq}`, channel_id: parent.channel_id, agent_name: who(c.req.header("authorization")!)!, text: body.text, metadata: body.data };
    messages.push(m);
    return c.json({ ok: true, data: m }, 201);
  });
  app.post("/v1/dm", async (c) => {
    const body = await c.req.json();
    const from = who(c.req.header("authorization")!)!;
    if (!agents.has(body.to)) return c.json({ ok: false, error: { code: "agent_not_found", message: `Agent "${body.to}" not found` } }, 404);
    const m = { id: `m${++seq}`, channel_id: `dmch_${pairOf(from, body.to)}`, agent_name: from, text: body.text, metadata: body.data };
    messages.push(m);
    return c.json({ ok: true, data: { conversation_id: `dm_${pairOf(from, body.to)}`, message: m } }, 201);
  });
  app.get("/v1/dm/conversations", (c) => {
    const me = who(c.req.header("authorization")!)!;
    const ids = new Set(messages.filter((m) => m.channel_id.startsWith("dmch_") && m.channel_id.slice(5).split("~").includes(me)).map((m) => `dm_${m.channel_id.slice(5)}`));
    // Shapes as in Relaycast's engine (engine/dm.ts): 1:1 conversations are type "1:1", group DMs "group".
    return c.json({ ok: true, data: [...ids].map((id) => ({ id, type: "1:1" })).concat([{ id: "gdm_1", type: "group" }]) });
  });
  app.get("/v1/search", (c) =>
    c.json({
      ok: true,
      data: messages.map((m) => {
        const ch = channels.find((x) => x.id === m.channel_id);
        return ch ? { id: m.id, channel_name: ch.name, agent_name: m.agent_name, text: m.text } : { id: m.id, conversation_id: `dm_${m.channel_id.slice(5)}`, channel_name: `dm-${m.channel_id.slice(5)}`, agent_name: m.agent_name, text: m.text };
      }),
    }),
  );
  app.get("/v1/inbox", (c) =>
    c.json({ ok: true, data: { unread_channels: channels.map((ch) => ({ channel_name: ch.name, unread_count: 1 })), mentions: [{ channel_name: "pit-ops", text: "x" }], unread_dms: [], recent_reactions: [] } }),
  );
  app.post("/v1/agent/node-token", (c) => c.json({ ok: true, data: { node_id: `node_${who(c.req.header("authorization")!)}`, node_name: "direct", token: `nt_live_${++seq}` } }));
  app.all("*", (c) => c.json({ ok: true, data: "should never be reached" }));

  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => app.fetch(new Request(input, init))) as typeof fetch;
  return {
    app,
    fetchFn,
    agents,
    messages,
    channels,
    calls,
    revokeUpstreamTokens: () => (revokeAll = true),
    setChannelsDown: (v: boolean) => (channelsDown = v),
  };
}

