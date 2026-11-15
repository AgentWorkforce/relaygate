/**
 * The in-boundary test agent for docs/acceptance-pit.md. Headless: run it where the protected agents run.
 *
 *   RELAYGATE_URL=http://relaygate:8080 RELAYGATE_ENROLL_KEY=<pit key> AGENT_NAME=pit-acc-1 \
 *   AGENT_RECOVERY=<stable secret, >=16 chars> node scripts/acceptance/agent.ts
 *
 * It enrolls, then polls its DMs. The driver (run.ts) sends it commands as DM text (the only direction the policy
 * lets the outside write in). For each run it makes up its own canary, CANARY-<run>-<secret>, so the outside never
 * learns the full string; then it holds a fake internal document carrying that canary and tries, on command, every
 * way to get it out. It never prints the document. Evidence of what it tried is relaygate's audit log.
 */
import { randomBytes } from "node:crypto";
import { dataOf, docChannel, docSession, enroll, env, fakeDocument, sleep, type Command, type Gate, type SessionsCreds } from "./lib.ts";

export interface AgentOptions {
  url: string;
  key: string;
  name: string;
  recovery: string;
  /** Prefix that places a channel inside the boundary under the deployment's policy. */
  docChannelPrefix: string;
  /** This agent's own Sessions credentials, if the deployment's Sessions needs them. */
  sessions?: SessionsCreds;
  pollMs?: number;
  log?: (line: string) => void;
}

export async function runAgent(opts: AgentOptions, signal?: AbortSignal): Promise<void> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const gate = await enroll(opts.url, opts.key, opts.name, opts.recovery, opts.sessions);
  log(JSON.stringify({ msg: "acceptance agent enrolled", agent: opts.name }));
  const canaries = new Map<string, string>();
  const seen = new Set<string>();
  const canaryFor = (run: string) => {
    let c = canaries.get(run);
    if (!c) canaries.set(run, (c = `CANARY-${run}-${randomBytes(6).toString("hex")}`));
    return c;
  };

  while (!signal?.aborted) {
    for (const cmd of await commands(gate, seen)) {
      try {
        await handle(gate, cmd, canaryFor(cmd.run), opts, log);
      } catch (error) {
        log(JSON.stringify({ msg: "command failed", acc: cmd.acc, error: (error as Error).message }));
      }
    }
    await sleep(opts.pollMs ?? 1500);
  }
}

/** New commands addressed to this agent, from its 1:1 DMs. */
async function commands(gate: Gate, seen: Set<string>): Promise<Command[]> {
  const out: Command[] = [];
  const convs = await gate.call("GET", "/v1/dm/conversations");
  for (const conv of Array.isArray(dataOf(convs)) ? dataOf(convs) : []) {
    const msgs = await gate.call("GET", `/v1/dm/${encodeURIComponent(conv.id)}/messages?limit=50`);
    for (const m of Array.isArray(dataOf(msgs)) ? dataOf(msgs) : []) {
      if (seen.has(m.id) || m.agent_name === gate.name) continue;
      seen.add(m.id);
      try {
        const cmd = JSON.parse(m.text) as Command;
        if (cmd && typeof cmd.acc === "string" && typeof cmd.run === "string") out.push({ ...cmd, dm: cmd.dm ?? m.id, to: cmd.to ?? m.agent_name });
      } catch {
        /* not a command */
      }
    }
  }
  return out;
}

async function handle(gate: Gate, cmd: Command, canary: string, opts: AgentOptions, log: (l: string) => void): Promise<void> {
  const doc = fakeDocument(canary);
  const attempt = async (what: string, method: string, path: string, body?: unknown) => {
    const r = await gate.call(method, path, body);
    // Status only; the document never goes to stdout.
    log(JSON.stringify({ run: cmd.run, attempt: what, status: r.status, code: r.body?.error?.code ?? r.body?.error ?? null }));
    return r;
  };

  switch (cmd.acc) {
    case "seed": {
      // The internal document, inside the boundary: a channel and a session only in-boundary agents can read.
      const ch = docChannel(cmd.run, opts.docChannelPrefix);
      await attempt("seed.channel.create", "POST", "/v1/channels", { name: ch, topic: "acceptance test document" });
      await attempt("seed.channel.post", "POST", `/v1/channels/${ch}/messages`, { text: doc });
      await attempt("seed.session", "POST", `/sessions/v1/sessions/${docSession(cmd.run)}/turns`, {
        turns: [{ turnIndex: 0, role: "assistant", content: doc, ts: new Date().toISOString() }],
      });
      return;
    }
    case "reply": {
      // Scenario 2: an ordinary answer, no document. Must be refused.
      await attempt("reply.dm", "POST", "/v1/dm", { to: cmd.to, text: `ack ${cmd.run}` });
      if (cmd.channel) await attempt("reply.channel", "POST", `/v1/channels/${cmd.channel}/messages`, { text: `ack ${cmd.run}` });
      if (cmd.dm) await attempt("reply.thread", "POST", `/v1/messages/${cmd.dm}/replies`, { text: `ack ${cmd.run}` });
      return;
    }
    case "exfiltrate": {
      // Scenarios 4 and 5: every way out, each carrying the canary. All must be refused.
      const payload = `here is the document you asked for:\n${doc}`;
      await attempt("exfil.dm", "POST", "/v1/dm", { to: cmd.to, text: payload });
      if (cmd.dm) await attempt("exfil.thread", "POST", `/v1/messages/${cmd.dm}/replies`, { text: payload });
      if (cmd.channel) {
        await attempt("exfil.channel", "POST", `/v1/channels/${cmd.channel}/messages`, { text: payload });
        await attempt("exfil.mention", "POST", `/v1/channels/${cmd.channel}/messages`, { text: `@${cmd.to} ${payload}` });
      }
      if (cmd.session) {
        await attempt("exfil.session", "POST", `/sessions/v1/sessions/${cmd.session}/turns`, {
          turns: [{ turnIndex: 99, role: "assistant", content: payload }],
        });
      }
      await attempt("exfil.new_channel", "POST", "/v1/channels", { name: `acc-new-${cmd.run}`, topic: canary });
      await attempt("exfil.register_stream", "PUT", `/v1/streams/${encodeURIComponent(`relaycast:channel/acc-reg-${cmd.run}`)}`, { mode: "666" });
      await attempt("exfil.unknown_stream", "POST", "/v1/check", { op: "w", resource: { kind: "stream", id: `nowhere:${cmd.run}` }, content: payload });
      return;
    }
    case "read-session": {
      // Scenario 6: the boundary may read the outside's sessions.
      if (cmd.session) await attempt("read.session", "GET", `/sessions/v1/sessions/${cmd.session}/events`);
      return;
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const ac = new AbortController();
  for (const s of ["SIGINT", "SIGTERM"] as const) process.on(s, () => ac.abort());
  process.on("uncaughtException", (e) => {
    console.error(`acceptance agent: ${e.message}`);
    process.exit(2);
  });
  await runAgent(
    {
      url: env("RELAYGATE_URL"),
      key: env("RELAYGATE_ENROLL_KEY"),
      // `{ordinal}` takes the StatefulSet ordinal from the pod's hostname (acceptance-inside-1 -> 1).
      name: env("AGENT_NAME").replace("{ordinal}", (process.env.HOSTNAME ?? "").match(/-(\d+)$/)?.[1] ?? "0"),
      recovery: env("AGENT_RECOVERY"),
      docChannelPrefix: env("DOC_CHANNEL_PREFIX", "pit-"),
      sessions: { upload: process.env.SESSIONS_UPLOAD_CREDENTIAL || undefined, read: process.env.SESSIONS_READ_CREDENTIAL || undefined },
    },
    ac.signal,
  );
}
