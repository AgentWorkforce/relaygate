/**
 * Shared helpers for the boundary acceptance test (docs/acceptance-pit.md). Self-contained: plain fetch and the
 * global WebSocket, no imports from src/, so the scripts run with `node <file>.ts` (Node 24 strips types) inside the
 * relaygate image or from a checkout. Nothing here knows any deployment's groups; names come from the environment.
 */

export interface Res {
  status: number;
  body: any;
}

import { createHash, randomBytes } from "node:crypto";

/** The caller's own Sessions credentials, when the deployment's Sessions needs them (relaygate forwards them). */
export interface SessionsCreds {
  upload?: string;
  read?: string;
  /**
   * Self-hosted Sessions: uploads use the native delivery protocol (whose account id is derived from the org and
   * workspace) and every read names its workspace. Without this, uploads use POST /v1/sessions/:id/turns.
   */
  native?: { orgId: string; workspaceId: string };
}

/** Session settings shared by every role, from the environment. */
export function sessionsFromEnv(upload?: string, read?: string): SessionsCreds {
  const orgId = process.env.SESSIONS_ORG_ID;
  const workspaceId = process.env.SESSIONS_WORKSPACE_ID;
  return { upload: upload || undefined, read: read || undefined, ...(orgId && workspaceId ? { native: { orgId, workspaceId } } : {}) };
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (value && typeof value === "object")
    return "{" + Object.keys(value).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson((value as any)[k])).join(",") + "}";
  return JSON.stringify(value);
}

/** What a session upload looks like to a person: the title, the user's prompt, and the assistant's reply. */
export interface Transcript {
  title: string;
  prompt: string;
  reply: string;
  /** Adding to someone else's session: events only, never the session record (its title stays the owner's). */
  append?: boolean;
}

/** Ingest nulls any number that passes the Luhn check (it could be a card number); keep timestamps clear of it. */
function notLuhn(ms: number): number {
  const luhn = (n: number) => {
    const d = String(n).split("").reverse().map(Number);
    return d.reduce((sum, x, i) => sum + (i % 2 ? (x * 2 > 9 ? x * 2 - 9 : x * 2) : x), 0) % 10 === 0;
  };
  while (luhn(ms)) ms += 1;
  return ms;
}

/**
 * One native delivery batch (relayhistory-delivery-v1) shaped like a real Claude Code session: a `session` record
 * with its title and first prompt, then a user and an assistant `session_event`. The role on each event is what
 * makes them messages, so the session gets a brief (title, summary) and readable events.
 */
export function nativeBatch(native: { orgId: string; workspaceId: string }, sessionId: string, t: Transcript) {
  const origin = "relaygate-acceptance";
  const id = `acc-${randomBytes(8).toString("hex")}`;
  const revision = Date.now();
  const t0 = notLuhn(Date.now());
  const t1 = notLuhn(t0 + 1000);
  const record = (recordId: string, kind: string, payload: Record<string, unknown>) => ({
    schema_version: 1,
    origin_id: origin,
    record_id: recordId,
    revision_id: `${recordId}:${revision}`,
    revision,
    kind,
    source: "claude",
    session_id: sessionId,
    operation: "upsert",
    payload,
  });
  return {
    protocolVersion: 1,
    batch: {
      schema_version: 1,
      origin_id: origin,
      batch_id: id,
      job_id: "relaygate-acceptance",
      generation: 1,
      destination_id: "relayhistory",
      instance_id: "relaygate-acceptance",
      account_id: "relayhistory:" + createHash("sha256").update(canonicalJson([native.orgId, native.workspaceId])).digest("hex"),
      mapping_version: "relayhistory-delivery-v1",
      records: [
        ...(t.append ? [] : [record(`session:${sessionId}`, "session", {
          title: t.title,
          cwd: "/acceptance",
          first_prompt: t.prompt,
          first_activity_ms: t0,
          last_activity_ms: t1,
          models_json: JSON.stringify(["claude-opus-5-5"]),
        })]),
        record(`${id}:u`, "session_event", { role: "user", text: t.prompt, ts_ms: t0, message_id: `${id}-u` }),
        record(`${id}:a`, "session_event", { role: "assistant", text: t.reply, ts_ms: t1, model: "claude-opus-5-5", message_id: `${id}-a` }),
      ],
    },
  };
}

export class Gate {
  url: string;
  token: string;
  name: string;
  sessions: SessionsCreds;

  constructor(url: string, token: string, name: string, sessions: SessionsCreds = {}) {
    this.url = url.replace(/\/$/, "");
    this.token = token;
    this.name = name;
    this.sessions = sessions;
  }

  /** Writes `text` into a session, in whichever upload protocol the deployment's Sessions speaks. */
  async sessionWrite(sessionId: string, t: Transcript): Promise<Res> {
    const once = () =>
      this.sessions.native
        ? this.call("POST", "/sessions/v1/delivery/batches", nativeBatch(this.sessions.native, sessionId, t))
        : this.call("POST", `/sessions/v1/sessions/${sessionId}/turns`, {
            turns: [
              { turnIndex: Date.now() % 100000, role: "user", content: t.prompt, ts: new Date().toISOString() },
              { turnIndex: (Date.now() % 100000) + 1, role: "assistant", content: t.reply, ts: new Date().toISOString() },
            ],
          });
    // A dropped connection is retried once; a duplicate test record is harmless.
    const r = await once();
    return r.status === 0 ? once() : r;
  }

  /**
   * Reads a session until `needle` appears (Sessions may store uploads asynchronously) or the wait runs out.
   * Returns the last response and whether the needle was found.
   */
  async sessionReadUntil(sessionId: string, needle: string, ms = ingestWaitMs()): Promise<{ res: Res; found: boolean }> {
    const start = Date.now();
    for (;;) {
      const res = await this.call("GET", `/sessions/v1/sessions/${sessionId}/events`);
      const found = res.status >= 200 && res.status < 300 && JSON.stringify(res.body ?? "").includes(needle);
      if (found || res.status === 403 || res.status === 401 || Date.now() - start > ms) return { res, found };
      await sleep(3000);
    }
  }

  async call(method: string, path: string, body?: unknown): Promise<Res> {
    // Self-hosted Sessions reads always name their workspace.
    if (method === "GET" && path.startsWith("/sessions/") && this.sessions.native && !/[?&]workspace=/.test(path)) {
      path += `${path.includes("?") ? "&" : "?"}workspace=${encodeURIComponent(this.sessions.native.workspaceId)}`;
    }
    const cred = path.startsWith("/sessions/") ? (method === "GET" ? this.sessions.read : this.sessions.upload) : undefined;
    // On Sessions routes the rg_ token goes in X-Relaygate-Token and the caller's Sessions credential in Authorization.
    if (cred) return request(this.url, method, path, cred, body, { "x-relaygate-token": this.token });
    return request(this.url, method, path, this.token, body);
  }
}

export async function request(base: string, method: string, path: string, token: string | undefined, body?: unknown, extra: Record<string, string> = {}): Promise<Res> {
  // A GET is idempotent: retry a dropped connection (port-forwards blip). Writes are never retried.
  for (let attempt = 0; ; attempt++) {
    const r = await requestOnce(base, method, path, token, body, extra);
    if (r.status !== 0 || method !== "GET" || attempt >= 3) return r;
    await sleep(1000 * (attempt + 1));
  }
}

async function requestOnce(base: string, method: string, path: string, token: string | undefined, body: unknown, extra: Record<string, string>): Promise<Res> {
  try {
    const res = await fetch(`${base.replace(/\/$/, "")}${path}`, {
      method,
      headers: { ...extra, ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: any = text;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      /* not JSON */
    }
    return { status: res.status, body: parsed };
  } catch (error) {
    return { status: 0, body: { error: "connection_failed", detail: (error as Error).message } };
  }
}

/** Registers (or recovers, with the same secret) an agent and returns a Gate acting as it. */
export async function enroll(base: string, key: string, name: string, recovery: string, sessions: SessionsCreds = {}): Promise<Gate> {
  const res = await request(base, "POST", "/v1/register", key, { name, recovery });
  if (res.status !== 200) throw new Error(`register ${name}: ${res.status} ${JSON.stringify(res.body)}`);
  return new Gate(base, res.body.token, name, sessions);
}

export const dataOf = (r: Res): any => (r.body && typeof r.body === "object" && "data" in r.body ? r.body.data : r.body);

/**
 * How long to wait for an upload to become readable. Self-hosted Sessions makes uploads readable on its indexer's
 * reconcile tick (every 5 minutes by default), so set ACCEPTANCE_INGEST_WAIT_MS=360000 there.
 */
export const ingestWaitMs = () => Number(process.env.ACCEPTANCE_INGEST_WAIT_MS || 45_000);

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === "") throw new Error(`${name} is required`);
  return v;
}

/** Commands the driver sends the pit test agent, as the text of a DM. */
export interface Command {
  acc: "seed" | "reply" | "read-session" | "answer";
  run: string;
  /** The outside agent to answer (and, after seeding, to try to leak to). */
  to?: string;
  /** A local channel and a local session the agent will try to write into. */
  channel?: string;
  session?: string;
  /** A DM message id to try to reply under. */
  dm?: string;
  /** Text the inside agent should find in a session it reads (logged as a boolean). */
  marker?: string;
}

export const docChannel = (run: string, prefix: string) => `${prefix}acc-doc-${run}`;
export const docSession = (run: string) => `acc-doc-${run}`;

/** A fake internal document. Never real data: names, numbers and the facility are invented. */
export function fakeDocument(canary: string): string {
  return [
    `INTERNAL - Discharge planning summary (synthetic test document) ${canary}`,
    "Facility: Northgate Test Clinic (fictional). Prepared for the boundary acceptance test.",
    "Patient: Jordan Testperson, DOB 1970-01-01, MRN TEST-000000 (all invented).",
    "Assessment: follow-up in 2 weeks; medication reconciliation pending; no real clinical content.",
    "Ops note: bed board sync scheduled nightly; escalation path via on-call coordinator.",
    `Canary for this run: ${canary}`,
  ].join("\n");
}

/** A minimal Relaycast node-transport client (through relaygate): collects every frame as text. */
export async function listen(gate: Gate, onFrame: (text: string) => void): Promise<{ close: () => void; opened: boolean; isOpen: () => boolean }> {
  const nt = await gate.call("POST", "/v1/agent/node-token", {});
  if (nt.status !== 200) return { close: () => {}, opened: false, isOpen: () => false };
  const d = dataOf(nt);
  const wsUrl = new URL("/v1/node/ws", gate.url);
  wsUrl.protocol = wsUrl.protocol === "https:" ? "wss:" : "ws:";
  wsUrl.searchParams.set("token", d.token);
  const ws = new WebSocket(wsUrl);
  const opened = await new Promise<boolean>((resolve) => {
    ws.addEventListener("open", () => resolve(true));
    ws.addEventListener("error", () => resolve(false));
    setTimeout(() => resolve(false), 10_000);
  });
  if (opened) {
    // The same registration the Relaycast SDK sends for an agent's direct node (fleet-wire node.register).
    ws.send(JSON.stringify({ v: 1, type: "node.register", node_id: d.node_id, name: d.node_name ?? gate.name, capabilities: [], max_agents: 1, tags: ["implicit", "direct", "sdk"], version: "relaygate-acceptance/1" }));
    ws.addEventListener("message", (e) => {
      const text = typeof e.data === "string" ? e.data : String(e.data);
      onFrame(text);
      try {
        const f = JSON.parse(text);
        if (f.type === "deliver") ws.send(JSON.stringify({ v: 1, type: "delivery.ack", agent: gate.name, up_to_seq: f.seq }));
        if (f.type === "ping") ws.send(JSON.stringify({ v: 1, type: "node.heartbeat", active_agents: 1, handlers_live: true }));
      } catch {
        /* ignore */
      }
    });
  }
  return { close: () => ws.close(), opened, isOpen: () => ws.readyState === WebSocket.OPEN };
}
