/**
 * Shared helpers for the boundary acceptance test (docs/acceptance-pit.md). Self-contained: plain fetch and the
 * global WebSocket, no imports from src/, so the scripts run with `node <file>.ts` (Node 24 strips types) inside the
 * relaygate image or from a checkout. Nothing here knows any deployment's groups; names come from the environment.
 */

export interface Res {
  status: number;
  body: any;
}

/** The caller's own Sessions credentials, when the deployment's Sessions needs them (relaygate forwards them). */
export interface SessionsCreds {
  upload?: string;
  read?: string;
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

  async call(method: string, path: string, body?: unknown): Promise<Res> {
    const cred = path.startsWith("/sessions/") ? (method === "GET" ? this.sessions.read : this.sessions.upload) : undefined;
    // On Sessions routes the rg_ token goes in X-Relaygate-Token and the caller's Sessions credential in Authorization.
    if (cred) return request(this.url, method, path, cred, body, { "x-relaygate-token": this.token });
    return request(this.url, method, path, this.token, body);
  }
}

export async function request(base: string, method: string, path: string, token: string | undefined, body?: unknown, extra: Record<string, string> = {}): Promise<Res> {
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

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === "") throw new Error(`${name} is required`);
  return v;
}

/** Commands the driver sends the pit test agent, as the text of a DM. */
export interface Command {
  acc: "seed" | "reply" | "exfiltrate" | "read-session";
  run: string;
  /** The local agent to answer / exfiltrate to. */
  to?: string;
  /** A local channel and a local session the agent will try to write into. */
  channel?: string;
  session?: string;
  /** A DM message id to try to reply under. */
  dm?: string;
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
export async function listen(gate: Gate, onFrame: (text: string) => void): Promise<{ close: () => void; opened: boolean }> {
  const nt = await gate.call("POST", "/v1/agent/node-token", {});
  if (nt.status !== 200) return { close: () => {}, opened: false };
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
    ws.send(JSON.stringify({ v: 1, type: "node.register", name: gate.name, node_id: d.node_id, capabilities: [], max_agents: 1 }));
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
  return { close: () => ws.close(), opened };
}
