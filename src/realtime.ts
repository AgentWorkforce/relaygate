import type { IncomingMessage, Server } from "node:http";
import type { Duplex } from "node:stream";
import type { Hono } from "hono";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import { guestEnded, principalFor, type Deps, type Env } from "./app.js";
import { canRead, channelStream, inboxStream, isDmChannelName, type RelaycastUpstream } from "./relaycast.js";
import type { Agent, NodeTokenRow } from "./store.js";

/**
 * Relaycast's realtime path (docs/contract.md, "Realtime"). An agent asks POST /v1/agent/node-token and gets an
 * rgn_ token; relaygate mints and keeps the upstream nt_live_ token. The agent opens /v1/node/ws with the rgn_ token,
 * relaygate opens the upstream socket with the real one, and:
 *
 * - client frames: only node.register (forced to the minted node id and no capabilities), node.heartbeat and
 *   delivery.ack for the agent itself are forwarded. agent.register, spawn, actions and the rest are refused;
 * - server frames: every deliver is checked against the caller's read access; action invocations and context
 *   updates are dropped;
 * - a socket closes as soon as the rg_ token behind it is revoked or a guest key ends.
 */

const CLIENT_FRAMES = new Set(["node.register", "node.heartbeat", "delivery.ack"]);
const PASS_SERVER_FRAMES = new Set(["ping", "reply", "error"]);

export function mountNodeToken(app: Hono<Env>, deps: Deps, upstream: RelaycastUpstream): void {
  app.post("/v1/agent/node-token", async (c) => {
    const agent = c.get("agent");
    let res;
    try {
      res = await upstream.asAgent(agent, "POST", "/v1/agent/node-token", {});
    } catch {
      return c.json({ ok: false, error: { code: "relaygate_upstream_unavailable" } }, 502);
    }
    if (res.status !== 200 && res.status !== 201) return c.json(res.body as object, res.status as 400);
    const body = res.body as { data?: { node_id: string; node_name: string; token: string } };
    const d = body.data;
    if (!d?.token || !d.node_id) return c.json({ ok: false, error: { code: "relaygate_upstream_bad_response" } }, 502);
    const token = deps.store.issueNodeToken({
      agentId: agent.id,
      agentTokenHash: c.get("tokenHash"),
      nodeId: d.node_id,
      upstreamSealed: upstream.cfg.box.seal(d.token),
    });
    deps.store.audit({ agentId: agent.id, action: "node_token", op: null, resourceKind: null, resourceId: null, decision: "allow", stage: "auth", reason: null });
    return c.json({ ...body, data: { ...d, token } }, 200);
  });
}

interface Conn {
  agent: Agent;
  row: NodeTokenRow;
  client: WebSocket;
  upstream: WebSocket;
}

export class NodeSockets {
  private wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024 });
  private conns = new Set<Conn>();
  private timer: NodeJS.Timeout;

  constructor(
    private deps: Deps,
    private upstream: RelaycastUpstream,
    revalidateMs = 5000,
  ) {
    this.timer = setInterval(() => this.revalidate(), revalidateMs);
    this.timer.unref();
  }

  get size(): number {
    return this.conns.size;
  }

  attach(server: Server): void {
    server.on("upgrade", (req, socket, head) => {
      // Nothing an unauthenticated client sends may throw out of the upgrade path and take the gateway down.
      try {
        this.onUpgrade(req, socket, head);
      } catch {
        socket.destroy();
      }
    });
  }

  /** The agent behind a node token, while the rg_ token that minted it still works. */
  private authenticate(token: string | undefined): { agent: Agent; row: NodeTokenRow } | undefined {
    if (!token?.startsWith("rgn_")) return undefined;
    const row = this.deps.store.nodeToken(token);
    if (!row) return undefined;
    const agent = this.deps.store.agentForTokenHash(row.agentTokenHash);
    if (!agent || agent.id !== row.agentId) return undefined;
    if (guestEnded(agent, this.deps.policy(), (this.deps.now ?? Date.now)())) return undefined;
    return { agent, row };
  }

  private onUpgrade(req: IncomingMessage, socket: Duplex, head: Buffer): void {
    let url: URL;
    try {
      url = new URL(req.url ?? "/", "http://relaygate");
    } catch {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return;
    }
    if (url.pathname !== "/v1/node/ws") {
      socket.end("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
      return;
    }
    const header = req.headers.authorization;
    const token = url.searchParams.get("token") ?? (header?.startsWith("Bearer ") ? header.slice(7).trim() : undefined);
    const auth = this.authenticate(token);
    if (!auth) {
      this.deps.store.audit({ agentId: null, action: "node_ws", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason: "bad_node_token" });
      socket.end("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      return;
    }
    this.wss.handleUpgrade(req, socket, head, (client) => this.open(client, auth.agent, auth.row));
  }

  private open(client: WebSocket, agent: Agent, row: NodeTokenRow): void {
    const target = new URL("v1/node/ws", this.upstream.cfg.url.endsWith("/") ? this.upstream.cfg.url : `${this.upstream.cfg.url}/`);
    target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
    let upstreamToken: string;
    try {
      upstreamToken = this.upstream.cfg.box.open(row.upstreamSealed);
    } catch {
      // Sealed under a different RELAYGATE_SECRET: this node token is dead; the client mints a new one.
      this.deps.store.audit({ agentId: agent.id, action: "node_ws", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason: "node_token_unsealable" });
      client.close(4401, "node token no longer valid");
      return;
    }
    target.searchParams.set("token", upstreamToken);
    const up = new WebSocket(target);
    const conn: Conn = { agent, row, client, upstream: up };
    this.conns.add(conn);
    this.deps.store.audit({ agentId: agent.id, action: "node_ws", op: null, resourceKind: null, resourceId: null, decision: "allow", stage: "auth", reason: "open" });

    const pending: string[] = [];
    up.on("open", () => {
      for (const frame of pending.splice(0)) up.send(frame);
    });
    client.on("message", (data) => {
      const out = this.fromClient(conn, data);
      if (out === undefined) return;
      if (up.readyState === WebSocket.OPEN) up.send(out);
      else if (pending.length < 100) pending.push(out);
    });
    up.on("message", (data) => {
      const out = this.fromUpstream(conn, data);
      if (out !== undefined && client.readyState === WebSocket.OPEN) client.send(out);
    });
    const end = (code: number, reason: string) => this.end(conn, code, reason);
    client.on("close", () => end(1000, "client closed"));
    up.on("close", (code) => end(code === 1005 || code === 1006 ? 1011 : code, "upstream closed"));
    client.on("error", () => end(1011, "client error"));
    up.on("error", () => end(1011, "upstream unavailable"));
  }

  private end(conn: Conn, code: number, reason: string): void {
    if (!this.conns.delete(conn)) return;
    const safe = code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1011;
    for (const ws of [conn.client, conn.upstream]) {
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        try {
          ws.close(safe, reason);
        } catch {
          ws.terminate();
        }
      }
    }
  }

  private fromClient(conn: Conn, data: RawData): string | undefined {
    const frame = parse(data);
    if (!frame || typeof frame.type !== "string" || !CLIENT_FRAMES.has(frame.type)) {
      this.refuse(conn, frame, "frame not allowed through relaygate");
      return undefined;
    }
    if (frame.type === "node.register") {
      // The node is the agent's own direct node, and it offers nothing upstream can invoke.
      return JSON.stringify({ ...frame, node_id: conn.row.nodeId, capabilities: [] });
    }
    if (frame.type === "delivery.ack" && frame.agent !== conn.agent.name) {
      this.refuse(conn, frame, "acks only for this agent");
      return undefined;
    }
    return JSON.stringify(frame);
  }

  private refuse(conn: Conn, frame: Record<string, unknown> | undefined, message: string): void {
    this.deps.store.audit({
      agentId: conn.agent.id,
      action: "node_ws.frame",
      op: null,
      resourceKind: null,
      resourceId: null,
      decision: "deny",
      stage: "mode",
      reason: `frame:${typeof frame?.type === "string" ? frame.type.slice(0, 40) : "invalid"}`,
    });
    if (typeof frame?.id === "string" && conn.client.readyState === WebSocket.OPEN) {
      conn.client.send(JSON.stringify({ v: 1, id: frame.id, type: "error", ok: false, code: "relaygate_denied", message }));
    }
  }

  private fromUpstream(conn: Conn, data: RawData): string | undefined {
    const frame = parse(data);
    if (!frame || typeof frame.type !== "string") return undefined;
    if (PASS_SERVER_FRAMES.has(frame.type)) return JSON.stringify(frame);
    if (frame.type !== "deliver") return undefined;
    return this.deliverable(conn, frame) ? JSON.stringify(frame) : undefined;
  }

  /** Whether a pushed delivery is something the agent may read. Anything unrecognised is dropped. */
  private deliverable(conn: Conn, frame: Record<string, unknown>): boolean {
    const { agent } = conn;
    if (frame.agent !== agent.name) return false;
    const payload = frame.payload as { type?: unknown; data?: Record<string, unknown> } | undefined;
    const kind = payload?.type;
    const channel = typeof payload?.data?.channel_name === "string" ? payload.data.channel_name : undefined;
    const principal = principalFor(agent, this.deps.policy());
    let stream: string | undefined;
    if (kind === "dm.received") stream = inboxStream(agent.name);
    else if ((kind === "message.created" || kind === "thread.reply") && channel) {
      // A thread reply under a DM arrives on the hidden DM channel: it is the agent's own inbox.
      stream = isDmChannelName(channel) ? inboxStream(agent.name) : channelStream(channel);
    }
    const ok = stream !== undefined && canRead(this.deps, principal, stream);
    if (!ok) {
      this.deps.store.audit({ agentId: agent.id, action: "node_ws.deliver", op: "r", resourceKind: "stream", resourceId: stream ?? null, decision: "deny", stage: "mode", reason: `deliver:${String(kind).slice(0, 40)}` });
    }
    return ok;
  }

  /** Closes every socket whose rg_ token has been revoked, or whose guest key has ended. */
  revalidate(): void {
    const now = (this.deps.now ?? Date.now)();
    for (const conn of this.conns) {
      const agent = this.deps.store.agentForTokenHash(conn.row.agentTokenHash);
      if (!agent || guestEnded(agent, this.deps.policy(), now)) {
        this.deps.store.audit({ agentId: conn.agent.id, action: "node_ws", op: null, resourceKind: null, resourceId: null, decision: "deny", stage: "auth", reason: "token_revoked" });
        this.end(conn, 4401, "token revoked");
      }
    }
  }

  close(): void {
    clearInterval(this.timer);
    for (const conn of this.conns) this.end(conn, 1001, "relaygate shutting down");
    this.wss.close();
  }
}

function parse(data: RawData): Record<string, unknown> | undefined {
  try {
    const v = JSON.parse(data.toString());
    return v && typeof v === "object" && !Array.isArray(v) ? v : undefined;
  } catch {
    return undefined;
  }
}
