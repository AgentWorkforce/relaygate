import type { Context, Hono } from "hono";
import { decide, longestPrefix, provenance, resolveStream, type Deps, type Env, type ResolvedStream } from "./app.js";
import { check, type Op, type Principal } from "./mode.js";
import type { Policy } from "./policy.js";
import type { Agent, SecretBox, Store } from "./store.js";

/**
 * The Relaycast proxy (docs/contract.md, "Tokens and the upstream credentials" and "Reads and lists").
 *
 * Relaycast has no act-as for agents, so relaygate registers every agent upstream under the same name with the
 * workspace key and keeps that agent's at_live_ token, sealed, server-side. Agents only ever hold rg_ tokens.
 *
 * Only the routes below are proxied; anything else answers 404 relaygate_route_not_proxied. Several Relaycast reads
 * skip membership checks (GET /messages/:id, /search, channel message lists), so relaygate checks each one itself.
 */

const MESSAGES: Record<string, string> = {
  relaygate_denied: "relaygate refused this request (permission bits)",
  relaygate_classified: "relaygate's classifier refused this content",
  relaygate_unavailable: "relaygate could not decide; retry with backoff",
  relaygate_bad_request: "relaygate could not read this request",
  relaygate_route_not_proxied: "this Relaycast route is not available through relaygate",
  relaygate_not_found: "not found",
  relaygate_conflict: "a concurrent request changed this; retry",
};

/** Errors on proxied routes use Relaycast's shape, so SDK clients surface relaygate's code and message. */
export function deny(c: Context, status: 400 | 401 | 403 | 404 | 409 | 413 | 415 | 502 | 503, code: string, extra: Record<string, unknown> = {}) {
  const detail = typeof extra.detail === "string" ? `: ${extra.detail}` : "";
  // relaygate couldn't decide (classifier, relay-control, an upstream): worth retrying shortly.
  const headers = status === 503 || status === 502 ? { "retry-after": "1" } : undefined;
  return c.json({ ok: false, error: { code, message: `${MESSAGES[code] ?? code}${detail}` }, ...extra }, status, headers);
}

export interface RelaycastConfig {
  /** Base URL of Relaycast, e.g. https://relaycast.internal */
  url: string;
  /** rk_live_ workspace key; used only to register agents upstream and recover their tokens. */
  workspaceKey: string;
  box: SecretBox;
  fetch?: typeof fetch;
}

export class UpstreamError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

interface UpstreamResponse {
  status: number;
  body: unknown;
  /** Retry-After from Relaycast (rate limits, overload), passed back to the caller. */
  retryAfter?: string;
}

export class RelaycastUpstream {
  private fetch: typeof fetch;
  private pending = new Map<string, Promise<string>>();

  constructor(
    readonly cfg: RelaycastConfig,
    private store: Store,
  ) {
    this.fetch = cfg.fetch ?? fetch;
  }

  private url(path: string): string {
    return new URL(path, this.cfg.url.endsWith("/") ? this.cfg.url : `${this.cfg.url}/`).toString();
  }

  async raw(method: string, path: string, token: string, body?: unknown, headers: Record<string, string> = {}): Promise<UpstreamResponse> {
    const res = await this.fetch(this.url(path.replace(/^\//, "")), {
      method,
      headers: { ...headers, authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = { ok: false, error: { code: "upstream_not_json" } };
    }
    return { status: res.status, body: parsed, retryAfter: res.headers.get("retry-after") ?? undefined };
  }

  /** The agent's upstream at_live_ token, registering the agent upstream on first use. */
  async agentToken(agent: Agent): Promise<string> {
    const stored = this.storedToken(agent);
    if (stored) return stored;
    // No row: register. A row that no longer opens (RELAYGATE_SECRET changed): take the identity over.
    return this.enroll(agent, this.store.upstreamAgent(agent.id) !== undefined);
  }

  private storedToken(agent: Agent): string | undefined {
    const row = this.store.upstreamAgent(agent.id);
    if (!row) return undefined;
    try {
      return this.cfg.box.open(row.tokenSealed);
    } catch {
      return undefined;
    }
  }

  /** Registers the agent upstream, or takes its identity over when the name already exists there. Single-flight per agent. */
  enroll(agent: Agent, takeover: boolean): Promise<string> {
    const inflight = this.pending.get(agent.id);
    if (inflight) return inflight;
    const p = this.doEnroll(agent, takeover).finally(() => this.pending.delete(agent.id));
    this.pending.set(agent.id, p);
    return p;
  }

  private async doEnroll(agent: Agent, takeover: boolean): Promise<string> {
    const key = this.cfg.workspaceKey;
    if (!takeover) {
      const created = await this.raw("POST", "/v1/agents", key, {
        name: agent.name,
        auto_join_general: false,
        metadata: { relaygate: { agent_id: agent.id } },
      });
      if (created.status === 200 || created.status === 201) {
        const data = dataOf(created.body) as { id: string; token: string };
        this.store.putUpstreamAgent(agent.id, data.id, this.cfg.box.seal(data.token));
        return data.token;
      }
      if (created.status !== 409) throw new UpstreamError(`upstream agent registration failed (${created.status})`, created.status);
    }
    // The name exists upstream (relaygate's database was reset, or the stored token stopped working): take it over.
    const found = await this.raw("GET", `/v1/agents/${encodeURIComponent(agent.name)}`, key);
    if (found.status !== 200) throw new UpstreamError(`upstream agent lookup failed (${found.status})`, found.status);
    const id = (dataOf(found.body) as { id: string }).id;
    const taken = await this.raw("POST", `/v1/agents/${encodeURIComponent(agent.name)}/takeover`, key, {
      expected_agent_id: id,
      actor: "relaygate",
      reason: "relaygate holds this agent's upstream credential",
      session_ref: `relaygate:${agent.id}`,
      node_id: "relaygate",
    });
    if (taken.status !== 200) throw new UpstreamError(`upstream agent takeover failed (${taken.status})`, taken.status);
    const token = (dataOf(taken.body) as { token: string }).token;
    this.store.putUpstreamAgent(agent.id, id, this.cfg.box.seal(token));
    this.store.audit({ agentId: agent.id, action: "upstream.takeover", op: null, resourceKind: "agent", resourceId: agent.name, decision: "allow", stage: null, reason: "relaycast" });
    return token;
  }

  /** Calls Relaycast as the agent. A 401 means the stored token stopped working: recover it once and retry. */
  async asAgent(agent: Agent, method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Promise<UpstreamResponse> {
    const used = await this.agentToken(agent);
    const first = await this.raw(method, path, used, body, headers);
    if (first.status !== 401) return first;
    // If another request already rotated the token, use that one rather than rotating again (which would
    // invalidate its retry). Concurrent takeovers are coalesced by enroll().
    const current = this.storedToken(agent);
    const next = current && current !== used ? current : await this.enroll(agent, true);
    return this.raw(method, path, next, body, headers);
  }

  /** Calls Relaycast with the workspace key (only for reads relaygate filters itself). */
  asWorkspace(method: string, path: string, body?: unknown): Promise<UpstreamResponse> {
    return this.raw(method, path, this.cfg.workspaceKey, body);
  }
}

const dataOf = (body: unknown): unknown => (body && typeof body === "object" && "data" in body ? (body as { data: unknown }).data : body);

// ---------------------------------------------------------------------------------------------------------------
// Stream ids relaygate derives from Relaycast requests.

export const channelStream = (name: string) => `relaycast:channel/${name}`;
export const inboxStream = (agentName: string) => `relaycast:inbox/${agentName}`;
/**
 * An agent's entry in the agent directory (GET /v1/agents, /v1/agents/:name). Only `r` is ever checked on it: it
 * lets a group see the agent (name, status, persona, card) without any right to message it or read its inbox.
 * Operator policy only: agents can't register these ids (PUT /v1/streams refuses them).
 */
export const AGENT_ENTRY_PREFIX = "relaycast:agent/";
export const agentEntry = (agentName: string) => `${AGENT_ENTRY_PREFIX}${agentName}`;

/**
 * An agent's directory entry, from operator policy only: an override for the exact id, else the longest prefix
 * default under `relaycast:agent/`. Registered stream rows never count (an agent could have registered one before
 * PUT /v1/streams refused these ids), and neither does a broader default such as `relaycast:`, so visibility only
 * widens when the operator writes a directory rule.
 */
export function directoryEntry(agentName: string, policy: Policy): ResolvedStream | undefined {
  const id = agentEntry(agentName);
  const override = policy.streamOverrides.find((o) => o.id === id);
  if (override) return { id, owner: null, gid: override.gid, mode: override.mode, classify: override.classify, acl: override.acl, source: "override" };
  const prefix = longestPrefix(id, policy);
  if (!prefix || !prefix.prefix.startsWith(AGENT_ENTRY_PREFIX)) return undefined;
  return { id, owner: null, gid: prefix.gid, mode: prefix.mode, classify: prefix.classify, acl: prefix.acl, source: "prefix" };
}

/** Relaycast stores DMs as hidden channels named dm-<pair>; they are never addressed as channels through relaygate. */
export const isDmChannelName = (name: string) => name.startsWith("dm-") || name.startsWith("dmch_");

const CHANNEL_NAME = /^[A-Za-z0-9._-]{1,128}$/;
/** A 1:1 DM conversation id (`dm_<pair key>`); group DMs use other prefixes and aren't proxied. */
const DM_ID = /^dm_[\x21-\x7e]{1,256}$/;

/** May this principal read the stream? Deterministic only (reads are never classified). */
export function canRead(deps: Deps, principal: Principal, id: string): boolean {
  const policy = deps.policy();
  const stream = resolveStream(id, deps.store, policy);
  return stream !== undefined && check(principal, stream, "r", policy.ceilings).allowed;
}

/** Every field of a write that carries content, flattened for the classifier. */
export function writeContent(body: Record<string, unknown>): string {
  const parts: string[] = [];
  if (typeof body.text === "string") parts.push(body.text);
  for (const key of ["blocks", "attachments", "data"] as const) {
    if (body[key] !== undefined) parts.push(JSON.stringify(body[key]));
  }
  return parts.join("\n");
}

/** Replaces any client-sent relaygate card with the verified one, so provenance can't be forged. */
export function stampProvenance(body: Record<string, unknown>, card: ReturnType<typeof provenance>): Record<string, unknown> {
  const data = body.data && typeof body.data === "object" && !Array.isArray(body.data) ? { ...(body.data as Record<string, unknown>) } : {};
  delete data.relaygate;
  return { ...body, data: { ...data, relaygate: card } };
}

// ---------------------------------------------------------------------------------------------------------------

type Ctx = Context<Env>;

export function mountRelaycast(app: Hono<Env>, deps: Deps, upstream: RelaycastUpstream): void {
  const { store } = deps;

  const audit = (c: Ctx, action: string, op: Op | null, id: string | null, decision: "allow" | "deny" | "unavailable", stage: "mode" | "classifier" | null, reason: string, policyVersion?: string) =>
    store.audit({ policyVersion, agentId: c.get("agent").id, action, op, resourceKind: id ? "stream" : null, resourceId: id, decision, stage, reason });

  const denied = (c: Ctx, op: Op, id: string) => deny(c, 403, "relaygate_denied", { op, resource: id });

  const pass = (c: Ctx, r: UpstreamResponse) => c.json(r.body as object, r.status as 200, r.retryAfter ? { "retry-after": r.retryAfter } : undefined);

  const forward = async (c: Ctx, method: string, path: string, body?: unknown) => {
    try {
      // Idempotency-Key passes through unchanged so client retries stay safe.
      const idem = c.req.header("idempotency-key");
      return await upstream.asAgent(c.get("agent"), method, path, body, idem ? { "idempotency-key": idem } : {});
    } catch (error) {
      console.error(JSON.stringify({ msg: "relaycast upstream error", error: (error as Error).message }));
      return { status: 502, body: { ok: false, error: { code: "relaygate_upstream_unavailable" } } };
    }
  };

  const pathWithQuery = (c: Ctx) => {
    const u = new URL(c.req.url);
    return `${u.pathname}${u.search}`;
  };

  const jsonBody = async (c: Ctx): Promise<Record<string, unknown> | undefined> => {
    const b = await c.req.json().catch(() => undefined);
    return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : undefined;
  };

  /** Mode check + classifier for a read, with audit. Returns a response when refused. */
  const gateRead = (c: Ctx, action: string, id: string) => {
    const principal = c.get("principal");
    const ok = canRead(deps, principal, id);
    audit(c, action, "r", id, ok ? "allow" : "deny", "mode", ok ? "read" : "read_denied");
    return ok ? undefined : denied(c, "r", id);
  };

  /** The full decision for a write (mode, then classifier), with audit. Returns a response when refused. */
  const gateWrite = async (c: Ctx, action: string, id: string, content: string) => {
    const d = await decide(deps, c.get("agent"), c.get("principal"), "w", id, content);
    switch (d.status) {
      case "allow":
        audit(c, action, "w", id, "allow", d.stage, d.reason, d.policyVersion);
        return undefined;
      case "deny":
        audit(c, action, "w", id, "deny", d.stage, d.reason, d.policyVersion);
        return deny(c, 403, d.error, { op: "w", resource: id });
      case "unavailable":
        audit(c, action, "w", id, "unavailable", d.stage, d.reason, d.policyVersion);
        return deny(c, 503, "relaygate_unavailable");
      case "invalid":
        return deny(c, 400, "relaygate_bad_request", { detail: d.reason });
    }
  };

  const channelParam = (c: Ctx): string | undefined => {
    const name = c.req.param("name");
    return name && CHANNEL_NAME.test(name) && !isDmChannelName(name) ? name : undefined;
  };

  /**
   * A channel's current name from its id, looked up fresh every time (a cached name would keep a renamed channel's
   * old permissions). Undefined when the channel isn't listed; an upstream failure is returned as is.
   */
  const channelNameFor = async (c: Ctx, channelId: string): Promise<string | undefined | UpstreamResponse> => {
    const list = await forward(c, "GET", "/v1/channels");
    if (list.status !== 200) return list;
    const ch = asArray(dataOf(list.body)).find((x) => x.id === channelId);
    return typeof ch?.name === "string" ? ch.name : undefined;
  };

  /**
   * Resolves the stream a message id belongs to by fetching it as the caller. A message in a channel maps to that
   * channel's stream. A DM message has no channel stream: only its author may address it by id.
   */
  const messageStream = async (
    c: Ctx,
    messageId: string,
  ): Promise<{ id: string } | { authorOnly: true; author: string; conversationId: string | undefined } | { status: number; body: unknown }> => {
    const res = await forward(c, "GET", `/v1/messages/${encodeURIComponent(messageId)}`);
    if (res.status !== 200) return res;
    const msg = dataOf(res.body) as Record<string, unknown>;
    const channelId = typeof msg.channel_id === "string" ? msg.channel_id : "";
    // Only a positively identified DM channel takes the DM path; anything unresolved is refused.
    if (channelId.startsWith("dmch_")) {
      return { authorOnly: true, author: String(msg.agent_name ?? ""), conversationId: `dm_${channelId.slice(5)}` };
    }
    const name = channelId ? await channelNameFor(c, channelId) : undefined;
    if (typeof name === "object") return name;
    if (name && !isDmChannelName(name)) return { id: channelStream(name) };
    return { status: 403, body: { ok: false, error: { code: "relaygate_denied", message: "relaygate could not place this message in a channel" } } };
  };

  /** Whether the caller participates in a 1:1 DM conversation. Relaycast checks participation on DM reads. */
  const inConversation = async (c: Ctx, conversationId: string | undefined): Promise<boolean> => {
    if (!conversationId || !DM_ID.test(conversationId)) return false;
    const res = await forward(c, "GET", `/v1/dm/${encodeURIComponent(conversationId)}/messages?limit=1`);
    return res.status === 200;
  };

  const MSG_ID = /^[A-Za-z0-9_-]{1,128}$/;

  // --- self ------------------------------------------------------------------------------------------------
  app.get("/v1/agent", async (c) => pass(c, await forward(c, "GET", "/v1/agent")));
  app.post("/v1/agents/heartbeat", async (c) => pass(c, await forward(c, "POST", "/v1/agents/heartbeat", (await jsonBody(c)) ?? {})));
  app.post("/v1/agents/disconnect", async (c) => pass(c, await forward(c, "POST", "/v1/agents/disconnect", (await jsonBody(c)) ?? {})));

  // --- agents (Relaycast refuses agent tokens here; relaygate answers with the workspace key, filtered) -------
  // An agent sees the agents it could message, whose inbox it may read, or whose directory entry
  // (relaycast:agent/<name>) it may read, and nothing else.
  const visibleAgent = (c: Ctx, name: unknown) => {
    if (typeof name !== "string") return false;
    if (name === c.get("agent").name) return true;
    const principal = c.get("principal");
    const ceilings = deps.policy().ceilings;
    // Visibility only: `r` on the agent's directory entry shows it, and grants nothing else.
    const entry = directoryEntry(name, deps.policy());
    if (entry && check(principal, entry, "r", ceilings).allowed) return true;
    const stream = resolveStream(inboxStream(name), store, deps.policy());
    if (!stream) return false;
    return check(principal, stream, "w", ceilings).allowed || check(principal, stream, "r", ceilings).allowed;
  };
  app.get("/v1/agents", async (c) => {
    const res = await upstream.asWorkspace("GET", pathWithQuery(c)).catch(() => ({ status: 502, body: { ok: false, error: { code: "relaygate_upstream_unavailable" } } }));
    if (res.status !== 200) return pass(c, res);
    return c.json({ ...(res.body as object), data: asArray(dataOf(res.body)).filter((a) => visibleAgent(c, a.name)) }, 200);
  });
  app.get("/v1/agents/:name", async (c) => {
    const name = c.req.param("name");
    if (!visibleAgent(c, name)) return deny(c, 404, "relaygate_not_found");
    const res = await upstream.asWorkspace("GET", `/v1/agents/${encodeURIComponent(name)}`).catch(() => ({ status: 502, body: { ok: false, error: { code: "relaygate_upstream_unavailable" } } }));
    return pass(c, res);
  });

  // --- self status and removal (Relaycast does these with the workspace key) ----------------------------
  app.patch("/v1/agent", async (c) => {
    const body = await jsonBody(c);
    if (!body) return deny(c, 400, "relaygate_bad_request", { detail: "JSON body required" });
    const allowed: Record<string, unknown> = {};
    for (const k of ["status", "persona", "metadata", "skills"]) if (k in body) allowed[k] = body[k];
    if (allowed.metadata && typeof allowed.metadata === "object" && !Array.isArray(allowed.metadata)) {
      const metadata = { ...(allowed.metadata as Record<string, unknown>) };
      delete metadata.relaygate;
      allowed.metadata = metadata;
    }
    const name = c.get("agent").name;
    audit(c, "agent.update", "w", `relaycast:agent/${name}`, "allow", null, Object.keys(allowed).join(",") || "nothing");
    try {
      await upstream.agentToken(c.get("agent"));
      return pass(c, await upstream.asWorkspace("PATCH", `/v1/agents/${encodeURIComponent(name)}`, allowed));
    } catch {
      return deny(c, 502, "relaygate_upstream_unavailable");
    }
  });

  app.delete("/v1/agent", async (c) => {
    const agent = c.get("agent");
    let res: UpstreamResponse;
    try {
      res = await upstream.asWorkspace("DELETE", `/v1/agents/${encodeURIComponent(agent.name)}`);
    } catch {
      return deny(c, 502, "relaygate_upstream_unavailable");
    }
    if (res.status >= 200 && res.status < 300) {
      // Gone upstream: its relaygate tokens and sockets go too. The name stays reserved for its owner.
      store.deleteUpstreamAgent(agent.id);
      store.revokeTokens(agent.id);
      deps.onTokensRevoked?.();
    }
    audit(c, "agent.delete", "w", `relaycast:agent/${agent.name}`, res.status < 300 ? "allow" : "deny", null, `upstream:${res.status}`);
    return pass(c, res);
  });

  // --- the delivery queue (the desktop broker's intake) ---------------------------------------------------
  // Each item is placed by its channel: a channel the caller may read, or a 1:1 DM (the caller's own inbox).
  // Anything else is never returned, and is failed upstream so it isn't redelivered.
  app.get("/v1/deliveries", async (c) => {
    const res = await forward(c, "GET", pathWithQuery(c));
    if (res.status !== 200) return pass(c, res);
    const items = asArray(dataOf(res.body));
    const principal = c.get("principal");
    const me = c.get("agent").name;
    // Channel names, looked up once and only if an item needs one. A failed lookup aborts the whole answer
    // (nothing is failed upstream): only a successful lookup can establish that an item is not readable.
    let names: Map<string, string> | undefined;
    if (items.some((i) => typeof i.channel_id === "string" && !i.channel_id.startsWith("dmch_"))) {
      const list = await forward(c, "GET", "/v1/channels");
      if (list.status !== 200 || !Array.isArray(dataOf(list.body))) return pass(c, list.status === 200 ? { status: 502, body: { ok: false, error: { code: "relaygate_upstream_unavailable" } } } : list);
      names = new Map(asArray(dataOf(list.body)).flatMap((ch) => (typeof ch.id === "string" && typeof ch.name === "string" ? [[ch.id, ch.name] as [string, string]] : [])));
    }
    const channelName = async (id: string) => names?.get(id);
    const kept: Array<Record<string, unknown>> = [];
    const refused: string[] = [];
    for (const item of items) {
      const channelId = typeof item.channel_id === "string" ? item.channel_id : "";
      let stream: string | undefined;
      if (channelId.startsWith("dmch_")) stream = inboxStream(me);
      else if (channelId) {
        const name = await channelName(channelId);
        if (name && !isDmChannelName(name)) stream = channelStream(name);
      }
      if (stream && canRead(deps, principal, stream)) kept.push(item);
      else if (typeof item.id === "string") refused.push(item.id);
    }
    for (const id of refused) {
      await forward(c, "POST", `/v1/deliveries/${encodeURIComponent(id)}/fail`, { error: "relaygate_denied", retryable: false });
    }
    audit(c, "deliveries.list", "r", null, "allow", "mode", `kept:${kept.length},refused:${refused.length}`);
    return c.json({ ...(res.body as object), data: kept }, 200);
  });
  for (const verb of ["ack", "fail", "defer"] as const) {
    app.post(`/v1/deliveries/:id/${verb}`, async (c) => {
      const id = c.req.param("id");
      if (!MSG_ID.test(id)) return deny(c, 400, "relaygate_bad_request", { detail: "invalid delivery id" });
      const body = verb === "ack" ? {} : ((await jsonBody(c)) ?? {});
      // Relaycast scopes these to the caller's own deliveries (404 for anyone else's).
      return pass(c, await forward(c, "POST", `/v1/deliveries/${encodeURIComponent(id)}/${verb}`, body));
    });
  }

  // --- channels --------------------------------------------------------------------------------------------
  app.get("/v1/channels", async (c) => {
    const res = await forward(c, "GET", pathWithQuery(c));
    if (res.status !== 200) return pass(c, res);
    const principal = c.get("principal");
    const visible = asArray(dataOf(res.body)).filter(
      (ch) => typeof ch.name === "string" && !isDmChannelName(ch.name) && canRead(deps, principal, channelStream(ch.name)),
    );
    return c.json({ ...(res.body as object), data: visible }, 200);
  });

  app.post("/v1/channels", async (c) => {
    const body = await jsonBody(c);
    const name = typeof body?.name === "string" ? body.name : "";
    if (!body || !CHANNEL_NAME.test(name) || isDmChannelName(name)) return deny(c, 400, "relaygate_bad_request", { detail: "invalid channel name" });
    const id = channelStream(name);
    const refused = await gateWrite(c, "channel.create", id, [body.topic, body.metadata && JSON.stringify(body.metadata)].filter(Boolean).join("\n"));
    if (refused) return refused;
    return pass(c, await forward(c, "POST", "/v1/channels", body));
  });

  app.get("/v1/channels/:name", async (c) => {
    const name = channelParam(c);
    if (!name) return deny(c, 404, "relaygate_route_not_proxied");
    return gateRead(c, "channel.get", channelStream(name)) ?? pass(c, await forward(c, "GET", pathWithQuery(c)));
  });

  app.get("/v1/channels/:name/messages", async (c) => {
    const name = channelParam(c);
    if (!name) return deny(c, 404, "relaygate_route_not_proxied");
    return gateRead(c, "channel.messages", channelStream(name)) ?? pass(c, await forward(c, "GET", pathWithQuery(c)));
  });

  // Joining subscribes the agent to the channel's deliveries, so it needs read.
  app.post("/v1/channels/:name/join", async (c) => {
    const name = channelParam(c);
    if (!name) return deny(c, 404, "relaygate_route_not_proxied");
    return gateRead(c, "channel.join", channelStream(name)) ?? pass(c, await forward(c, "POST", c.req.path, {}));
  });

  for (const verb of ["leave", "mute", "unmute"] as const) {
    app.post(`/v1/channels/:name/${verb}`, async (c) => {
      const name = channelParam(c);
      if (!name) return deny(c, 404, "relaygate_route_not_proxied");
      return pass(c, await forward(c, "POST", c.req.path, {}));
    });
  }

  app.post("/v1/channels/:name/messages", async (c) => {
    const name = channelParam(c);
    if (!name) return deny(c, 404, "relaygate_route_not_proxied");
    const body = await jsonBody(c);
    if (!body) return deny(c, 400, "relaygate_bad_request", { detail: "JSON body required" });
    // `from` lets a node post as another agent upstream; relaygate never forwards it.
    delete body.from;
    const id = channelStream(name);
    const refused = await gateWrite(c, "channel.post", id, writeContent(body));
    if (refused) return refused;
    const card = provenance(c.get("agent"), c.get("principal"), deps.policy());
    return pass(c, await forward(c, "POST", c.req.path, stampProvenance(body, card)));
  });

  // --- messages and threads --------------------------------------------------------------------------------
  const byMessage = (op: Op, action: string, handler: (c: Ctx, messageId: string, body?: Record<string, unknown>) => Promise<Response>) =>
    async (c: Ctx) => {
      const messageId = c.req.param("id") ?? "";
      if (!MSG_ID.test(messageId)) return deny(c, 400, "relaygate_bad_request", { detail: "invalid message id" });
      const body = op === "w" ? await jsonBody(c) : undefined;
      if (op === "w" && !body) return deny(c, 400, "relaygate_bad_request", { detail: "JSON body required" });
      const where = await messageStream(c, messageId);
      if ("status" in where) return pass(c, where);
      if ("authorOnly" in where) {
        // A DM message (or a thread under it) is readable by id only by the two participants. Writes into DM threads
        // aren't modelled (which inbox would they go to?), so they are refused; answer with POST /v1/dm.
        // Reading a DM is reading your own inbox, so the inbox's read bit (and any ceiling) applies too.
        const me = c.get("agent").name;
        const mine =
          op === "r" &&
          canRead(deps, c.get("principal"), inboxStream(me)) &&
          (where.author === me || (await inConversation(c, where.conversationId)));
        audit(c, action, op, `relaycast:message/${messageId}`, mine ? "allow" : "deny", "mode", mine ? "dm_author" : "dm_message");
        return mine ? handler(c, messageId, body) : denied(c, op, `relaycast:message/${messageId}`);
      }
      if (op === "r") {
        const refused = gateRead(c, action, where.id);
        if (refused) return refused;
      } else {
        const refused = await gateWrite(c, action, where.id, writeContent(body!));
        if (refused) return refused;
      }
      return handler(c, messageId, body);
    };

  app.get("/v1/messages/:id", byMessage("r", "message.get", async (c) => pass(c, await forward(c, "GET", c.req.path))));
  app.get("/v1/messages/:id/replies", byMessage("r", "thread.get", async (c) => pass(c, await forward(c, "GET", pathWithQuery(c)))));
  app.post(
    "/v1/messages/:id/replies",
    byMessage("w", "thread.reply", async (c, _id, body) => {
      delete body!.from;
      const card = provenance(c.get("agent"), c.get("principal"), deps.policy());
      return pass(c, await forward(c, "POST", c.req.path, stampProvenance(body!, card)));
    }),
  );
  app.get("/v1/messages/:id/reactions", byMessage("r", "reaction.list", async (c) => pass(c, await forward(c, "GET", c.req.path))));
  app.post("/v1/messages/:id/reactions", byMessage("w", "reaction.add", async (c, _id, body) => pass(c, await forward(c, "POST", c.req.path, body))));
  app.delete("/v1/messages/:id/reactions/:emoji", byMessage("r", "reaction.remove", async (c) => pass(c, await forward(c, "DELETE", c.req.path))));
  app.post("/v1/messages/:id/read", byMessage("r", "message.read", async (c) => pass(c, await forward(c, "POST", c.req.path, {}))));

  // --- DMs -------------------------------------------------------------------------------------------------
  app.post("/v1/dm", async (c) => {
    const body = await jsonBody(c);
    const me = c.get("agent").name;
    const to = typeof body?.to === "string" ? (body.to === "@self" ? me : body.to.replace(/^@/, "")) : "";
    if (!body || !/^[A-Za-z0-9._:-]{1,128}$/.test(to)) return deny(c, 400, "relaygate_bad_request", { detail: "invalid recipient" });
    // As on channel posts, `from` (a node-only sender override upstream) is never forwarded.
    delete body.from;
    const id = inboxStream(to);
    const refused = await gateWrite(c, "dm.send", id, writeContent(body));
    if (refused) return refused;
    // A relaygate agent registered before eager enrollment (or whose enrollment was deferred) may not exist upstream
    // yet; create it so the DM has somewhere to go.
    const recipient = store.agentByName(to);
    if (recipient && !store.upstreamAgent(recipient.id)) await upstream.agentToken(recipient).catch(() => undefined);
    const card = provenance(c.get("agent"), c.get("principal"), deps.policy());
    return pass(c, await forward(c, "POST", "/v1/dm", stampProvenance({ ...body, to }, card)));
  });

  app.get("/v1/dm/conversations", async (c) => {
    const res = await forward(c, "GET", pathWithQuery(c));
    if (res.status !== 200) return pass(c, res);
    // Group DMs aren't modelled by relaygate; only 1:1 conversations are listed, and only while the caller may read
    // its own inbox (each entry carries the last message).
    const inbox = canRead(deps, c.get("principal"), inboxStream(c.get("agent").name));
    // Relaycast marks 1:1 conversations `type: "1:1"` (group DMs are "group") with `dm_` ids.
    const visible = inbox ? asArray(dataOf(res.body)).filter((conv) => conv.type === "1:1" && typeof conv.id === "string" && DM_ID.test(conv.id)) : [];
    return c.json({ ...(res.body as object), data: visible }, 200);
  });

  app.get("/v1/dm/:cid/messages", async (c) => {
    const cid = c.req.param("cid");
    if (!DM_ID.test(cid)) return deny(c, 404, "relaygate_route_not_proxied");
    // Upstream checks participation; reading your own conversations is reading your own inbox.
    const refused = gateRead(c, "dm.messages", inboxStream(c.get("agent").name));
    return refused ?? pass(c, await forward(c, "GET", pathWithQuery(c)));
  });

  // --- search and inbox (filtered) -------------------------------------------------------------------------
  app.get("/v1/search", async (c) => {
    const res = await forward(c, "GET", pathWithQuery(c));
    if (res.status !== 200) return pass(c, res);
    const principal = c.get("principal");
    const me = c.get("agent").name;
    // Upstream search spans every channel and every DM; keep channel hits the caller may read and DM hits it wrote.
    const visible = asArray(dataOf(res.body)).filter((hit) => {
      const ch = typeof hit.channel_name === "string" ? hit.channel_name : undefined;
      if (ch && !isDmChannelName(ch) && !hit.conversation_id) return canRead(deps, principal, channelStream(ch));
      return hit.agent_name === me;
    });
    audit(c, "search", "r", null, "allow", "mode", `filtered:${visible.length}`);
    return c.json({ ...(res.body as object), data: visible }, 200);
  });

  app.get("/v1/inbox", async (c) => {
    const res = await forward(c, "GET", pathWithQuery(c));
    if (res.status !== 200) return pass(c, res);
    const principal = c.get("principal");
    const data = (dataOf(res.body) ?? {}) as Record<string, unknown>;
    const readable = (item: Record<string, unknown>) =>
      typeof item.channel_name === "string" && !isDmChannelName(item.channel_name) && canRead(deps, principal, channelStream(item.channel_name));
    const filtered = {
      ...data,
      unread_channels: asArray(data.unread_channels).filter(readable),
      mentions: asArray(data.mentions).filter(readable),
      // DM entries carry message text: they are the caller's inbox.
      unread_dms: canRead(deps, principal, inboxStream(c.get("agent").name)) ? asArray(data.unread_dms) : [],
      recent_reactions: asArray(data.recent_reactions).filter(readable),
    };
    return c.json({ ...(res.body as object), data: filtered }, 200);
  });

}

function asArray(v: unknown): Array<Record<string, unknown>> {
  return Array.isArray(v) ? (v.filter((x) => x && typeof x === "object") as Array<Record<string, unknown>>) : [];
}
