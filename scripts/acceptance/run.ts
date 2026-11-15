/**
 * Boundary acceptance driver (docs/acceptance-pit.md). Plays the outside agents, commands the in-boundary test
 * agents over DM, and prints PASS / FAIL / SKIP / MANUAL per scenario with relaygate audit lines as evidence.
 *
 * Required: RELAYGATE_URL, OUTSIDE_KEY (enrollment key of the outside group), ADMIN_TOKEN (relaygate admin token).
 * In-boundary agents, one of:
 *   INSIDE_KEY=<key>            run two test agents in this process (dry run)
 *   INSIDE_AGENTS=a,b           use test agents already running elsewhere (scripts/acceptance/agent.ts)
 * Optional: RUN_ID, OUTSIDE_NAME_PREFIX (local-), INSIDE_NAME_PREFIX (pit-), DOC_CHANNEL_PREFIX (pit-),
 *   OUTSIDE_CHANNEL_PREFIX (""), POLICY_FILE (for the draft-policy checks), RELAYCAST_DIRECT_URL,
 *   RG_DOWN_CMD / RG_UP_CMD, RG_POLICY_FLIP_CMD / RG_POLICY_RESTORE_CMD,
 *   OUTSIDE_SESSIONS_UPLOAD / OUTSIDE_SESSIONS_READ and INSIDE_SESSIONS_UPLOAD / INSIDE_SESSIONS_READ (the callers'
 *   own Sessions credentials, when the deployment's Sessions needs them; relaygate forwards them).
 * Defaults match examples/policy.double-pit.json; nothing here is specific to a customer.
 */
import { execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { runAgent } from "./agent.ts";
import { dataOf, docChannel, docSession, enroll, env, listen, request, sleep, type Command, type Gate } from "./lib.ts";

type Verdict = "PASS" | "FAIL" | "SKIP" | "MANUAL";
interface Result {
  id: number;
  title: string;
  verdict: Verdict;
  notes: string[];
  evidence: string[];
}

const URL_ = env("RELAYGATE_URL").replace(/\/$/, "");
const OUTSIDE_KEY = env("OUTSIDE_KEY");
const ADMIN = env("ADMIN_TOKEN");
const RUN = process.env.RUN_ID || `${Date.now().toString(36)}${randomBytes(2).toString("hex")}`;
const OUT_PREFIX = process.env.OUTSIDE_NAME_PREFIX ?? "local-";
const IN_PREFIX = process.env.INSIDE_NAME_PREFIX ?? "pit-";
const DOC_PREFIX = process.env.DOC_CHANNEL_PREFIX ?? "pit-";
const OUT_CH_PREFIX = process.env.OUTSIDE_CHANNEL_PREFIX ?? "";
const CANARY_PREFIX = `CANARY-${RUN}`;
const results: Result[] = [];

function record(id: number, title: string, verdict: Verdict, notes: string[] = [], evidence: string[] = []) {
  results.push({ id, title, verdict, notes, evidence });
  console.log(`\n[${verdict}] ${id}. ${title}`);
  for (const n of notes) console.log(`    ${n}`);
  for (const e of evidence) console.log(`    audit: ${e}`);
}

const fmt = (r: any) =>
  `#${r.seq} ${r.agent_name ?? "-"} ${r.action} ${r.op ?? ""} ${r.resource_id ?? ""} -> ${r.decision}/${r.stage ?? "-"} (${r.reason ?? ""}) policy=${r.policy_version ?? "-"}`;

async function audit(after: number, agent?: string): Promise<any[]> {
  const q = new URLSearchParams({ after: String(after), limit: "1000", ...(agent ? { agent } : {}) });
  const r = await request(URL_, "GET", `/admin/v1/audit?${q}`, ADMIN);
  if (r.status !== 200) throw new Error(`audit: ${r.status} ${JSON.stringify(r.body)}`);
  return r.body.rows;
}

async function auditHead(): Promise<number> {
  const rows = await audit(0);
  let last = rows.at(-1)?.seq ?? 0;
  // Page to the end.
  for (let more = rows.length === 1000; more; ) {
    const next = await audit(last);
    if (next.length) last = next.at(-1).seq;
    more = next.length === 1000;
  }
  return last;
}

/** Waits until `agent` has audit rows for every action in `actions` after `after`. */
async function waitFor(agent: string, after: number, actions: string[], ms = 90_000): Promise<any[]> {
  const start = Date.now();
  for (;;) {
    const rows = await audit(after, agent);
    if (actions.every((a) => rows.some((r) => r.action === a))) return rows;
    if (Date.now() - start > ms) return rows;
    await sleep(2000);
  }
}

async function policyVersion(): Promise<string | undefined> {
  return (await request(URL_, "GET", "/readyz", undefined)).body?.policy_version;
}

async function command(from: Gate, to: string, cmd: Command) {
  const r = await from.call("POST", "/v1/dm", { to, text: JSON.stringify(cmd) });
  return r;
}

const ok = (s: number) => s >= 200 && s < 300;

async function main() {
  console.log(`relaygate boundary acceptance, run ${RUN}, target ${URL_}`);
  const ready = await request(URL_, "GET", "/readyz", undefined);
  if (ready.status !== 200) throw new Error(`relaygate not ready: ${ready.status}`);
  console.log(`policy version ${ready.body.policy_version}`);

  // In-boundary agents.
  const inline = !!process.env.INSIDE_KEY;
  const insideNames = inline ? [`${IN_PREFIX}acc-1-${RUN}`, `${IN_PREFIX}acc-2-${RUN}`] : env("INSIDE_AGENTS").split(",").map((s) => s.trim());
  const ac = new AbortController();
  if (inline) {
    for (const name of insideNames) {
      void runAgent(
        {
          url: URL_,
          key: env("INSIDE_KEY"),
          name,
          recovery: randomBytes(16).toString("hex"),
          docChannelPrefix: DOC_PREFIX,
          sessions: { upload: process.env.INSIDE_SESSIONS_UPLOAD || undefined, read: process.env.INSIDE_SESSIONS_READ || undefined },
          log: () => {},
        },
        ac.signal,
      ).catch((e) => console.error(`agent ${name}: ${e.message}`));
    }
  }
  const [pitA, pitB] = insideNames as [string, string];

  // Outside agents.
  const outsideSessions = { upload: process.env.OUTSIDE_SESSIONS_UPLOAD || undefined, read: process.env.OUTSIDE_SESSIONS_READ || undefined };
  const localA = await enroll(URL_, OUTSIDE_KEY, `${OUT_PREFIX}acc-1-${RUN}`, randomBytes(16).toString("hex"), outsideSessions);
  const localB = await enroll(URL_, OUTSIDE_KEY, `${OUT_PREFIX}acc-2-${RUN}`, randomBytes(16).toString("hex"), outsideSessions);
  const localChannel = `${OUT_CH_PREFIX}acc-${RUN}`;
  const localSession = `acc-local-${RUN}`;
  const frames: string[] = [];
  const socket = await listen(localA, (t) => frames.push(t));
  await sleep(inline ? 4000 : 1000);
  let head = await auditHead();

  // --- 1. outside -> inside DM and stream post --------------------------------------------------------------
  {
    const dm = await command(localA, pitA, { acc: "seed", run: RUN });
    const seeded = await waitFor(pitA, head, ["channel.create", "channel.post"]);
    const post = await localA.call("POST", `/v1/channels/${docChannel(RUN, DOC_PREFIX)}/messages`, { text: `context for ${RUN}` });
    const mine = await audit(head, localA.name);
    const delivered = seeded.some((r) => r.action === "channel.post" && r.decision === "allow");
    record(
      1,
      "outside agent DMs an inside agent and posts into an inside stream: delivered",
      ok(dm.status) && delivered && (ok(post.status) || post.status === 404) ? "PASS" : "FAIL",
      [
        `DM ${dm.status}; inside agent acted on it (seeded its document): ${delivered}`,
        `post into ${docChannel(RUN, DOC_PREFIX)}: ${post.status}${post.status === 404 ? " (channel not created yet upstream)" : ""}`,
      ],
      [...mine.filter((r) => r.action === "dm.send" || r.action === "channel.post").map(fmt), ...seeded.map(fmt)],
    );
    head = Math.max(head, ...seeded.map((r) => r.seq), ...mine.map((r) => r.seq));
  }

  // --- 6. outside session upload (first, so it exists before the inside agent tries to write it) -------------
  {
    const up = await localA.call("POST", `/sessions/v1/sessions/${localSession}/turns`, {
      turns: [{ turnIndex: 0, role: "assistant", content: `outside work log ${RUN}`, ts: new Date().toISOString() }],
    });
    if (up.status === 404) {
      record(6, "outside session upload is stored and readable inside", "SKIP", ["Sessions proxy not enabled on this relaygate (/sessions 404)"]);
    } else {
      const peer = await localB.call("GET", `/sessions/v1/sessions/${localSession}/events`);
      await command(localA, pitA, { acc: "read-session", run: RUN, session: localSession });
      const rows = await waitFor(pitA, head, ["session.read"]);
      const insideRead = rows.find((r) => r.action === "session.read" && r.resource_id === localSession);
      record(
        6,
        "outside session upload is stored; readable by another outside agent and by an inside agent",
        ok(up.status) && ok(peer.status) && insideRead?.decision === "allow" ? "PASS" : "FAIL",
        [`upload ${up.status}; outside peer read ${peer.status}; inside read ${insideRead?.decision ?? "not seen"}`, "MANUAL: confirm the admin sees it in the dashboard (scenario 13)."],
        rows.filter((r) => r.action === "session.read").map(fmt),
      );
      head = Math.max(head, ...rows.map((r) => r.seq));
    }
  }

  // An outside channel both outside agents use.
  await localA.call("POST", "/v1/channels", { name: localChannel, topic: "acceptance outside channel" });
  await localA.call("POST", `/v1/channels/${localChannel}/join`, {});
  const lastDm = await command(localA, pitA, { acc: "reply", run: RUN, channel: localChannel });
  const dmId = dataOf(lastDm)?.message?.id;

  // --- 2. inside agent answers the outside: refused --------------------------------------------------------
  {
    const rows = await waitFor(pitA, head, ["dm.send", "channel.post"]);
    const attempts = rows.filter((r) => ["dm.send", "channel.post", "thread.reply"].includes(r.action));
    const allDenied = attempts.length >= 2 && attempts.every((r) => r.decision === "deny");
    record(2, "inside agent replies to the outside agent (DM, outside stream, thread): refused", allDenied ? "PASS" : "FAIL", [`${attempts.length} attempts, all denied: ${allDenied}`], attempts.map(fmt));
    head = Math.max(head, ...rows.map((r) => r.seq));
  }

  // --- 3. outside reads the inside document: refused --------------------------------------------------------
  {
    const ch = docChannel(RUN, DOC_PREFIX);
    const checks = [
      ["channel messages", await localA.call("GET", `/v1/channels/${ch}/messages`)],
      ["channel", await localA.call("GET", `/v1/channels/${ch}`)],
      ["join", await localA.call("POST", `/v1/channels/${ch}/join`, {})],
      ["session events", await localA.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/events`)],
      ["session turns", await localA.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/turns`)],
    ] as const;
    const search = await localA.call("GET", `/v1/search?q=${encodeURIComponent(CANARY_PREFIX)}`);
    const list = await localA.call("GET", "/v1/channels");
    const listed = (dataOf(list) ?? []).some((c: any) => c.name === ch);
    const leaked = JSON.stringify(search.body).includes(CANARY_PREFIX);
    const refused = checks.every(([, r]) => r.status === 403 || (r.status === 404 && String(JSON.stringify(r.body)).includes("relaygate")));
    const rows = await audit(head, localA.name);
    record(
      3,
      "outside agent reads the inside document (stream, history, session, search): refused",
      refused && !leaked && !listed ? "PASS" : "FAIL",
      [...checks.map(([n, r]) => `${n}: ${r.status}`), `search hit the canary: ${leaked}; doc channel listed: ${listed}`],
      rows.filter((r) => r.decision === "deny").map(fmt),
    );
    head = Math.max(head, ...rows.map((r) => r.seq));
  }

  // --- 4 + 5. ask for the document; every way out refused; canary nowhere outside ---------------------------
  {
    await command(localA, pitA, { acc: "exfiltrate", run: RUN, channel: localChannel, session: localSession, dm: dmId });
    await command(localB, pitB, { acc: "seed", run: RUN });
    await command(localB, pitB, { acc: "exfiltrate", run: RUN, to: localB.name, channel: localChannel, session: localSession });
    const expected = ["dm.send", "channel.post", "session.write", "channel.create", "stream.register", "check"];
    const rowsA = await waitFor(pitA, head, expected);
    const rowsB = await waitFor(pitB, head, expected);
    // Every write the inside agents attempted, except seeding their own in-boundary document. Their reads (polling
    // their own inbox, reading outside sessions) aren't ways out.
    const exfil = [...rowsA, ...rowsB].filter((r) => r.op === "w" && !(r.resource_id ?? "").includes(`acc-doc-${RUN}`));
    const leaks = exfil.filter((r) => r.decision !== "deny");
    await sleep(3000);
    const found = await canarySweep([localA, localB], localChannel, localSession, frames);
    record(
      4,
      "outside agent asks an inside agent to paste the document: no reply delivered; canary nowhere outside",
      leaks.length === 0 && exfil.length > 0 && found.length === 0 ? "PASS" : "FAIL",
      [`exfiltration attempts ${exfil.length}, allowed ${leaks.length}`, found.length ? `CANARY FOUND: ${found.join(", ")}` : `canary ${CANARY_PREFIX}… absent from inbox, DMs, channel, search, session, realtime frames`],
      leaks.map(fmt),
    );
    const doors = new Map<string, any[]>();
    for (const r of exfil) doors.set(r.action, [...(doors.get(r.action) ?? []), r]);
    const missing = expected.filter((a) => !doors.has(a));
    record(
      5,
      "inside agent side doors (outside channel, outside session, new stream, stream registration, unknown stream, mention): refused",
      missing.length === 0 && leaks.length === 0 ? "PASS" : "FAIL",
      [...[...doors].map(([a, rs]) => `${a}: ${rs.map((r) => r.decision).join(",")}`), ...(missing.length ? [`not observed: ${missing.join(", ")}`] : [])],
      exfil.map(fmt),
    );
    head = Math.max(head, ...rowsA.map((r) => r.seq), ...rowsB.map((r) => r.seq));
  }

  // --- 7. outside appends to an inside session: accepted, classified, not readable back ---------------------
  {
    const app = await localA.call("POST", `/sessions/v1/sessions/${docSession(RUN)}/turns`, {
      turns: [{ turnIndex: 50, role: "user", content: `outside context for ${RUN}` }],
    });
    const back = await localA.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/events`);
    const rows = (await audit(head, localA.name)).filter((r) => r.resource_id === docSession(RUN));
    const write = rows.find((r) => r.action === "session.write");
    if (app.status === 404) record(7, "outside appends to an inside session", "SKIP", ["Sessions proxy not enabled"]);
    else
      record(
        7,
        "outside agent appends to an inside session: accepted and classified; can't read it back",
        ok(app.status) && write?.stage === "classifier" && back.status === 403 ? "PASS" : "FAIL",
        [`append ${app.status} (stage ${write?.stage ?? "?"}); read back ${back.status}`],
        rows.map(fmt),
      );
    head = Math.max(head, ...rows.map((r) => r.seq));
  }

  // --- 8. inside session: outside can't read it -------------------------------------------------------------
  {
    const r1 = await localA.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/turns`);
    const r2 = await localB.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/metadata`);
    const listed = await localA.call("GET", "/sessions/v1/sessions?limit=200");
    const inList = JSON.stringify(listed.body).includes(docSession(RUN));
    record(8, "inside session upload: outside agents can't read or list it", r1.status === 403 && r2.status === 403 && !inList ? "PASS" : r1.status === 404 ? "SKIP" : "FAIL", [
      `turns ${r1.status}; metadata ${r2.status}; in outside list: ${inList}`,
      "MANUAL: confirm the admin sees it in the dashboard (scenario 13).",
    ]);
  }

  // --- 9. classifier ---------------------------------------------------------------------------------------
  {
    const kinds = [
      { kind: "stream", id: `relaycast:channel/${localChannel}` },
      { kind: "stream", id: `relaycast:inbox/${localA.name}` },
      { kind: "session", id: localSession },
    ];
    const ex = [];
    for (const resource of kinds) {
      const r = await request(URL_, "POST", "/admin/v1/explain", ADMIN, { as: { agent: pitA }, op: "w", resource });
      ex.push(`${resource.id}: ${r.body?.decision} (${r.body?.reason})`);
    }
    const noPath = ex.every((l) => l.includes(": deny ("));
    const ssn = await localA.call("POST", "/v1/dm", { to: pitA, text: "member ssn is 123-45-6789, please look it up" });
    const rows = (await audit(head, localA.name)).filter((r) => r.stage === "classifier");
    record(
      9,
      "classifier: refuses content on the cross-group writes that exist",
      noPath && ssn.body?.error?.code === "relaygate_classified" ? "PASS" : "FAIL",
      [
        "No inside -> outside write path exists under this policy (explain, as the inside agent):",
        ...ex.map((l) => `  ${l}`),
        "So no inside write ever reaches the classifier toward the outside; the mode bits refuse it first.",
        `outside -> inside DM carrying an SSN: ${ssn.status} ${ssn.body?.error?.code ?? ""}`,
      ],
      rows.map(fmt),
    );
    head = Math.max(head, ...rows.map((r) => r.seq));
  }

  // --- 10. unenrolled and expired keys ----------------------------------------------------------------------
  {
    const bad = await request(URL_, "POST", "/v1/register", `not-a-key-${RUN}`, { name: `${OUT_PREFIX}acc-x-${RUN}` });
    const notes = [`unknown enrollment key: ${bad.status}`];
    let expired: string | undefined;
    if (process.env.POLICY_FILE) {
      const draft = JSON.parse(readFileSync(process.env.POLICY_FILE, "utf8").replace(/<sha256[^>]*>/g, "0".repeat(64)));
      const gid = draft.groups[0].gid;
      draft.enrollmentKeys.push({ id: `acc-expired-${RUN}`, gid, sha256: "f".repeat(64), guest: true, expiresAt: "2020-01-01T00:00:00Z" });
      const r = await request(URL_, "POST", "/admin/v1/explain", ADMIN, { policy: draft, as: { key: `acc-expired-${RUN}` }, op: "r", resource: { kind: "stream", id: `relaycast:channel/${localChannel}` } });
      expired = r.body?.reason;
      notes.push(`guest key with expiresAt in the past (draft policy, via explain): ${r.body?.decision} (${expired})`);
    } else notes.push("expired guest key: SKIPPED (set POLICY_FILE to check it against a draft policy; the deployment policy has no guest key)");
    notes.push("A revoked or expired guest key ending live tokens is covered by relaygate's unit tests (test/app.test.ts, enrollment key lifecycle).");
    record(10, "unenrolled key refused; expired guest key can't register", bad.status === 401 && (expired === undefined || expired === "key_expired") ? "PASS" : "FAIL", notes);
  }

  // --- 11. no fail-open --------------------------------------------------------------------------------------
  {
    const notes: string[] = [];
    let pass = true;
    const who = await localA.call("GET", "/v1/whoami");
    const nt = await localA.call("POST", "/v1/agent/node-token", {});
    const leakedCred = /at_live_|nt_live_|rk_live_|rth_(st|at)_/.test(JSON.stringify([who.body, nt.body]));
    notes.push(`upstream credentials in anything a client received: ${leakedCred}`);
    pass &&= !leakedCred;
    if (process.env.RELAYCAST_DIRECT_URL) {
      const direct = await request(process.env.RELAYCAST_DIRECT_URL, "GET", "/v1/agent", localA.token);
      notes.push(`rg_ token straight at Relaycast: ${direct.status}`);
      pass &&= direct.status === 401 || direct.status === 403 || direct.status === 0;
    } else notes.push("rg_ token straight at Relaycast: SKIPPED (set RELAYCAST_DIRECT_URL)");
    if (process.env.RG_DOWN_CMD && process.env.RG_UP_CMD) {
      execSync(process.env.RG_DOWN_CMD, { stdio: "inherit" });
      await sleep(5000);
      const down = await localA.call("POST", "/v1/dm", { to: pitA, text: "while down" });
      notes.push(`request while relaygate is down: ${down.status} ${down.body?.error ?? ""} (anything but 2xx; nothing can reach upstream without relaygate)`);
      pass &&= !ok(down.status);
      execSync(process.env.RG_UP_CMD, { stdio: "inherit" });
      for (let i = 0; i < 60 && (await request(URL_, "GET", "/readyz", undefined)).status !== 200; i++) await sleep(2000);
    } else notes.push("relaygate down: SKIPPED (set RG_DOWN_CMD and RG_UP_CMD, e.g. kubectl scale --replicas=0/1)");
    record(11, "relaygate down / bypass: no fail-open, no upstream credentials on clients", pass ? "PASS" : "FAIL", notes);
  }

  // --- 12. policy change takes effect -------------------------------------------------------------------------
  if (process.env.RG_POLICY_FLIP_CMD && process.env.RG_POLICY_RESTORE_CMD) {
    const before = await policyVersion();
    const waitVersion = async (pred: (v?: string) => boolean) => {
      for (let i = 0; i < 90; i++) {
        const v = await policyVersion();
        if (pred(v)) return v;
        await sleep(2000);
      }
      return undefined;
    };
    execSync(process.env.RG_POLICY_FLIP_CMD, { stdio: "inherit" });
    const flipped = await waitVersion((v) => v !== undefined && v !== before);
    const h1 = await auditHead();
    await command(localA, pitA, { acc: "reply", run: `${RUN}f`, to: localA.name });
    const allowed = (await waitFor(pitA, h1, ["dm.send"])).find((r) => r.action === "dm.send");
    execSync(process.env.RG_POLICY_RESTORE_CMD, { stdio: "inherit" });
    const restored = await waitVersion((v) => v === before);
    const h2 = await auditHead();
    await command(localA, pitA, { acc: "reply", run: `${RUN}r`, to: localA.name });
    const deniedAgain = (await waitFor(pitA, h2, ["dm.send"])).find((r) => r.action === "dm.send");
    record(
      12,
      "policy change takes effect (flip one ACL, rerun scenario 2, restore)",
      flipped && allowed?.decision === "allow" && restored === before && deniedAgain?.decision === "deny" ? "PASS" : "FAIL",
      [`policy ${before} -> ${flipped ?? "no change seen"} -> ${restored ?? "not restored"}`],
      [allowed, deniedAgain].filter(Boolean).map(fmt),
    );
  } else record(12, "policy change takes effect", "SKIP", ["set RG_POLICY_FLIP_CMD and RG_POLICY_RESTORE_CMD (see the runbook)"]);

  record(13, "admin sees outside and inside sessions per person in the dashboard", "MANUAL", ["follow the runbook: docs/acceptance-pit.md, scenario 13"]);

  socket.close();
  ac.abort();
  const fails = results.filter((r) => r.verdict === "FAIL");
  console.log(`\nrun ${RUN}: ${results.map((r) => `${r.id}:${r.verdict}`).join(" ")}`);
  console.log(fails.length ? `${fails.length} FAILED` : "no failures");
  process.exit(fails.length ? 1 : 0);
}

/** Every place the outside can read, searched for this run's canary prefix. */
async function canarySweep(outside: Gate[], channel: string, session: string, frames: string[]): Promise<string[]> {
  const hits: string[] = [];
  const has = (v: unknown) => JSON.stringify(v ?? "").includes(CANARY_PREFIX);
  for (const g of outside) {
    const convs = dataOf(await g.call("GET", "/v1/dm/conversations")) ?? [];
    for (const c of Array.isArray(convs) ? convs : []) {
      if (has(dataOf(await g.call("GET", `/v1/dm/${encodeURIComponent(c.id)}/messages?limit=100`)))) hits.push(`${g.name} DM ${c.id}`);
    }
    if (has((await g.call("GET", "/v1/inbox")).body)) hits.push(`${g.name} inbox`);
    if (has((await g.call("GET", `/v1/channels/${channel}/messages`)).body)) hits.push(`${g.name} #${channel}`);
    if (has((await g.call("GET", `/v1/search?q=${encodeURIComponent(CANARY_PREFIX)}`)).body)) hits.push(`${g.name} search`);
    if (has((await g.call("GET", `/sessions/v1/sessions/${session}/events`)).body)) hits.push(`${g.name} session ${session}`);
    if (has((await g.call("GET", `/sessions/v1/sessions/${session}/turns`)).body)) hits.push(`${g.name} session turns`);
  }
  if (frames.some((f) => f.includes(CANARY_PREFIX))) hits.push("realtime frames");
  return hits;
}

main().catch((error) => {
  console.error(`acceptance driver error: ${(error as Error).message}`);
  process.exit(2);
});
