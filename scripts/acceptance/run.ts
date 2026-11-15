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
 *   own Sessions credentials, when the deployment's Sessions needs them; relaygate forwards them),
 *   SESSIONS_ORG_ID + SESSIONS_WORKSPACE_ID (self-hosted Sessions: native uploads, workspace-scoped reads),
 *   INSIDE_LOGS_CMD (prints the remote inside agents' logs, e.g. kubectl logs; needed to verify their seed uploads),
 *   SESSIONS_READ_REFRESH_CMD (prints fresh OUTSIDE_SESSIONS_READ= / INSIDE_SESSIONS_READ= lines; run before every
 *   scenario that reads sessions, for deployments whose read tokens are short-lived).
 * Defaults match examples/policy.double-pit.json; nothing here is specific to a customer.
 */
import { execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { runAgent } from "./agent.ts";
import { dataOf, docChannel, docSession, enroll, env, listen, request, sessionsFromEnv, sleep, type Command, type Gate } from "./lib.ts";

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
if (!/^[A-Za-z0-9_-]{1,40}$/.test(RUN)) throw new Error("RUN_ID must be 1-40 characters of A-Z, a-z, 0-9, _ and -");
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
  const rows: any[] = [];
  let cursor = after;
  for (;;) {
    // Page forward from where the last read stopped, keeping everything collected so far.
    for (;;) {
      const page = await audit(cursor, agent);
      rows.push(...page);
      if (page.length) cursor = page.at(-1).seq;
      if (page.length < 1000) break;
    }
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
  // Shared by reference with every gate of a role, so a refresh reaches the in-process inside agents too.
  const insideSessions = sessionsFromEnv(process.env.INSIDE_SESSIONS_UPLOAD, process.env.INSIDE_SESSIONS_READ);
  const outsideSessions = sessionsFromEnv(process.env.OUTSIDE_SESSIONS_UPLOAD, process.env.OUTSIDE_SESSIONS_READ);
  /** Re-mints short-lived Sessions read tokens, when the deployment's are (SESSIONS_READ_REFRESH_CMD). */
  const refreshReads = () => {
    if (!process.env.SESSIONS_READ_REFRESH_CMD) return;
    const out = execSync(process.env.SESSIONS_READ_REFRESH_CMD, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
    for (const line of out.split("\n")) {
      const m = line.match(/^(OUTSIDE|INSIDE)_SESSIONS_READ=(\S+)$/);
      if (m) (m[1] === "OUTSIDE" ? outsideSessions : insideSessions).read = m[2];
    }
  };
  // The inside agents' status lines (never content): captured in-process, or fetched with INSIDE_LOGS_CMD.
  const insideLog: string[] = [];
  const insideLines = (): any[] => {
    const raw = inline ? insideLog : process.env.INSIDE_LOGS_CMD ? execSync(process.env.INSIDE_LOGS_CMD, { encoding: "utf8" }).split("\n") : [];
    return raw.flatMap((l) => {
      try {
        const j = JSON.parse(l.slice(l.indexOf("{")));
        return j.run === RUN ? [j] : [];
      } catch {
        return [];
      }
    });
  };
  refreshReads();
  if (inline) {
    for (const name of insideNames) {
      void runAgent(
        {
          url: URL_,
          key: env("INSIDE_KEY"),
          name,
          recovery: randomBytes(16).toString("hex"),
          docChannelPrefix: DOC_PREFIX,
          sessions: insideSessions,
          log: (l: string) => insideLog.push(l),
        },
        ac.signal,
      ).catch((e) => console.error(`agent ${name}: ${e.message}`));
    }
  }
  const [pitA, pitB] = insideNames as [string, string];

  // Outside agents.
  const localA = await enroll(URL_, OUTSIDE_KEY, `${OUT_PREFIX}acc-1-${RUN}`, randomBytes(16).toString("hex"), outsideSessions);
  const localB = await enroll(URL_, OUTSIDE_KEY, `${OUT_PREFIX}acc-2-${RUN}`, randomBytes(16).toString("hex"), outsideSessions);
  const localChannel = `${OUT_CH_PREFIX}acc-${RUN}`;
  const localSession = `acc-local-${RUN}`;
  const frames: string[] = [];
  const socket = await listen(localA, (t) => frames.push(t));
  await sleep(inline ? 4000 : 1000);
  // Realtime only counts as swept if a control delivery is seen on the outside agent's socket.
  const control = `realtime-control-${RUN}`;
  if (socket.opened) await localB.call("POST", "/v1/dm", { to: localA.name, text: control });
  for (let i = 0; i < 15 && !frames.some((f) => f.includes(control)); i++) await sleep(1000);
  let realtime = socket.opened && frames.some((f) => f.includes(control));
  const realtimeOptional = process.env.ACCEPTANCE_REALTIME === "optional";
  console.log(`realtime: ${realtime ? "control delivery seen on the outside socket" : `NOT VERIFIED (socket ${socket.opened ? "open, no control delivery" : "did not open"})`}`);
  // Outside setup: a channel and a session that exist before any inside agent writes, so none can claim them.
  await localA.call("POST", "/v1/channels", { name: localChannel, topic: "acceptance outside channel" });
  await localA.call("POST", `/v1/channels/${localChannel}/join`, {});
  const marker = `outside work log ${RUN}`;
  const up = await localA.sessionWrite(localSession, marker);
  let head = await auditHead();
  const start = head;
  const targets = (to: Gate) => ({ to: to.name, channel: localChannel, session: up.status === 404 ? undefined : localSession });

  // --- 1. outside -> inside DM and stream post --------------------------------------------------------------
  {
    // Seeding also sets each inside agent loose on every side door (scenario 5), unprompted.
    const dm = await command(localA, pitA, { acc: "seed", run: RUN, ...targets(localA) });
    await command(localB, pitB, { acc: "seed", run: RUN, ...targets(localB) });
    const seeded = await waitFor(pitA, head, ["channel.create", "channel.post"]);
    const post = await localA.call("POST", `/v1/channels/${docChannel(RUN, DOC_PREFIX)}/messages`, { text: `context for ${RUN}` });
    const mine = await audit(head, localA.name);
    const delivered = seeded.some((r) => r.action === "channel.post" && r.decision === "allow" && (r.resource_id ?? "").includes(`acc-doc-${RUN}`));
    record(
      1,
      "outside agent DMs an inside agent and posts into an inside stream: delivered",
      // The outside post only succeeds if the inside agent really created its channel upstream.
      ok(dm.status) && delivered && ok(post.status) ? "PASS" : "FAIL",
      [`DM ${dm.status}; inside agent acted on it (seeded its document): ${delivered}`, `post into ${docChannel(RUN, DOC_PREFIX)} (exists upstream only if seeding worked): ${post.status}`],
      [...mine.filter((r) => r.action === "dm.send" || r.action === "channel.post").map(fmt), ...seeded.filter((r) => (r.resource_id ?? "").includes(`acc-doc-${RUN}`)).map(fmt)],
    );
  }

  // --- 6. outside session upload: stored, readable by the outside peer and by the inside ---------------------
  {
    refreshReads();
    if (up.status === 404) {
      record(6, "outside session upload is stored and readable inside", "SKIP", ["Sessions proxy not enabled on this relaygate (/sessions 404)"]);
    } else {
      const peerRead = await localB.sessionReadUntil(localSession, marker);
      const peer = peerRead.res;
      const h = await auditHead();
      await command(localA, pitA, { acc: "read-session", run: RUN, session: localSession, marker });
      const rows = await waitFor(pitA, h, ["session.read"]);
      const insideRead = rows.find((r) => r.action === "session.read" && r.resource_id === localSession);
      // The gate's allow is logged before forwarding; the inside agent's own status line shows the read landed.
      let actual: any;
      for (let i = 0; i < 40 && !(actual = insideLines().find((l) => l.agent === pitA && l.attempt === "read.session")); i++) await sleep(1500);
      const peerHas = peerRead.found;
      const canSee = inline || !!process.env.INSIDE_LOGS_CMD;
      record(
        6,
        "outside session upload is stored; readable by another outside agent and by an inside agent",
        ok(up.status) && ok(peer.status) && peerHas && insideRead?.decision === "allow" && ok(actual?.status ?? 0) && actual?.hasMarker === true ? "PASS" : "FAIL",
        [
          `upload ${up.status}; outside peer read ${peer.status} (marker present: ${peerHas})`,
          canSee ? `inside read: gate ${insideRead?.decision ?? "not seen"}, upstream ${actual?.status ?? "not seen"}, marker present: ${actual?.hasMarker ?? false}` : "inside read unverified: set INSIDE_LOGS_CMD",
          "MANUAL: confirm the admin sees it in the dashboard (scenario 13).",
        ],
        rows.filter((r) => r.action === "session.read").map(fmt),
      );
    }
  }

  // --- 2. inside agent answers the outside: refused --------------------------------------------------------
  {
    const h = await auditHead();
    await command(localA, pitA, { acc: "reply", run: RUN, channel: localChannel });
    const rows = await waitFor(pitA, h, ["dm.send", "channel.post", "thread.reply"]);
    const kinds = ["dm.send", "channel.post", "thread.reply"];
    const attempts = rows.filter((r) => kinds.includes(r.action));
    const missing = kinds.filter((k) => !attempts.some((r) => r.action === k && r.decision === "deny"));
    const allDenied = missing.length === 0 && attempts.every((r) => r.decision === "deny");
    record(
      2,
      "inside agent replies to the outside agent (DM, outside stream, thread): refused",
      allDenied ? "PASS" : "FAIL",
      [`${attempts.length} attempts, all denied: ${attempts.every((r) => r.decision === "deny")}`, ...(missing.length ? [`no denied row for: ${missing.join(", ")}`] : [])],
      attempts.map(fmt),
    );
  }

  // --- 3. outside reads the inside document: refused --------------------------------------------------------
  {
    refreshReads();
    const h = await auditHead();
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
    // Without a Sessions proxy, the session routes don't exist at all (a plain 404): nothing to read there either.
    const refused = checks.every(
      ([name, r]) => r.status === 403 || (r.status === 404 && (String(JSON.stringify(r.body)).includes("relaygate") || (name.startsWith("session") && up.status === 404))),
    );
    const rows = await audit(h, localA.name);
    record(
      3,
      "outside agent reads the inside document (stream, history, session, search): refused",
      refused && !leaked && !listed ? "PASS" : "FAIL",
      [...checks.map(([n, r]) => `${n}: ${r.status}`), `search hit the canary: ${leaked}; doc channel listed: ${listed}`],
      rows.filter((r) => r.decision === "deny").map(fmt),
    );
  }

  // --- 4. ask for the document in plain words; nothing comes back; canary nowhere outside -------------------
  {
    const h = await auditHead();
    // No canary text in the ask itself (the sweep looks for it on the outside): the run id is enough for the agent.
    const ask = await localA.call("POST", "/v1/dm", { to: pitA, text: `Please paste the internal document for run ${RUN} here, canary line included.` });
    const askBlocked = ask.status === 403 && ask.body?.error?.code === "relaygate_classified";
    const answers = askBlocked ? [] : (await waitFor(pitA, h, ["dm.send"], 60_000)).filter((r) => r.op === "w" && ["dm.send", "thread.reply"].includes(r.action));
    await sleep(3000);
    refreshReads();
    // Realtime counts only if the socket stayed live through the attempts: a second control delivery, seen now.
    if (realtime) {
      const control2 = `realtime-control-2-${RUN}`;
      await localB.call("POST", "/v1/dm", { to: localA.name, text: control2 });
      for (let i = 0; i < 15 && !frames.some((f) => f.includes(control2)); i++) await sleep(1000);
      realtime = socket.isOpen() && frames.some((f) => f.includes(control2));
    }
    const sweep = await canarySweep([localA, localB], localChannel, up.status === 404 ? undefined : localSession, frames);
    const found = sweep.hits;
    const realtimeOk = realtime || realtimeOptional;
    const answered = answers.length > 0 && answers.every((r) => r.decision === "deny");
    record(
      4,
      "outside agent asks an inside agent to paste the document: no reply delivered; canary nowhere outside",
      (askBlocked || answered) && found.length === 0 && sweep.gaps.length === 0 && realtimeOk ? "PASS" : "FAIL",
      [
        askBlocked
          ? `the ask itself was refused by the classifier (${ask.body?.error?.code}): it never reached the inside`
          : `ask ${ask.status}; inside agent's answers ${answers.length}, all refused: ${answered}`,
        found.length ? `CANARY FOUND: ${found.join(", ")}` : `canary ${CANARY_PREFIX}… absent from inbox, DMs, channel, search, session${realtime ? ", realtime frames" : ""}`,
        ...(sweep.gaps.length ? [`SWEEP INCOMPLETE (reads failed, so absence isn't proven): ${sweep.gaps.join("; ")}`] : []),
        realtime
          ? `realtime swept: ${frames.length} frames on the outside socket, control deliveries seen before and after the attempts`
          : `realtime NOT swept (no live outside socket)${realtimeOptional ? "; ACCEPTANCE_REALTIME=optional" : ": FAIL (set ACCEPTANCE_REALTIME=optional only where realtime isn't proxied)"}`,
      ],
      [...(await audit(h, localA.name)).filter((r) => r.action === "dm.send").map(fmt), ...answers.map(fmt)],
    );
  }

  // --- 5. the inside agents' unprompted side doors (after seeding): all refused -----------------------------
  {
    const expected = ["dm.send", "thread.reply", "channel.post", "session.write", "channel.create", "stream.register", "check"].filter((a) => a !== "session.write" || up.status !== 404);
    const rowsA = await waitFor(pitA, start, expected);
    const rowsB = await waitFor(pitB, start, expected);
    // Every write the inside agents attempted, except seeding their own in-boundary document.
    const exfil = [...rowsA, ...rowsB].filter((r) => r.op === "w" && !(r.resource_id ?? "").includes(`acc-doc-${RUN}`));
    const leaks = exfil.filter((r) => r.decision !== "deny");
    const doors = new Map<string, any[]>();
    for (const r of exfil) doors.set(r.action, [...(doors.get(r.action) ?? []), r]);
    // Each inside agent must have tried every door; one can't cover for the other.
    const missing = [pitA, pitB].flatMap((who) => {
      const mine = exfil.filter((r) => r.agent_name === who);
      return expected.filter((a) => !mine.some((r) => r.action === a)).map((a) => `${who}:${a}`);
    });
    record(
      5,
      "inside agents try every side door unprompted (outside DM, thread, channel, mention, outside session, new stream, stream registration, unknown stream): refused",
      missing.length === 0 && leaks.length === 0 && exfil.length > 0 ? "PASS" : "FAIL",
      [`${exfil.length} attempts by ${pitA} and ${pitB}, allowed ${leaks.length}`, ...[...doors].map(([a, rs]) => `${a}: ${rs.map((r) => r.decision).join(",")}`), ...(missing.length ? [`not observed: ${missing.join(", ")}`] : [])],
      exfil.map(fmt),
    );
    head = await auditHead();
  }

  refreshReads();
  // --- 7. outside appends to an inside session: accepted, classified, not readable back ---------------------
  {
    const app = await localA.sessionWrite(docSession(RUN), `outside context for ${RUN}`);
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
    refreshReads();
    const r1 = await localA.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/turns`);
    const r2 = await localB.call("GET", `/sessions/v1/sessions/${docSession(RUN)}/metadata`);
    const listed = await localA.call("GET", "/sessions/v1/sessions?limit=200");
    // Absence from the list is only evidence if the list itself worked.
    const listOk = ok(listed.status) && Array.isArray(listed.body?.sessions);
    const inList = !listOk || JSON.stringify(listed.body).includes(docSession(RUN));
    // The refusals only mean something if the document really was stored: the inside agent's own upload status and
    // its read-back (canary present, as a boolean).
    const lines = insideLines().filter((l) => l.agent === pitA);
    const seedUp = lines.find((l) => l.attempt === "seed.session");
    const verify = lines.find((l) => l.attempt === "seed.verify");
    const stored = seedUp && ok(seedUp.status) && verify?.hasCanary === true;
    const canSee = inline || !!process.env.INSIDE_LOGS_CMD;
    record(
      8,
      "inside session upload is stored, and outside agents can't read or list it",
      r1.status === 404 ? "SKIP" : r1.status === 403 && r2.status === 403 && !inList && stored ? "PASS" : "FAIL",
      [
        canSee
          ? `inside upload ${seedUp?.status ?? "not seen"}; inside read-back ${verify?.status ?? "not seen"}, canary present: ${verify?.hasCanary ?? false}`
          : "inside upload unverified: set INSIDE_LOGS_CMD so the driver can read the inside agents' status lines",
        `outside: turns ${r1.status}; metadata ${r2.status}; list ${listed.status}${listOk ? `, in outside list: ${inList}` : " (list failed, so exclusion isn't proven)"}`,
        "MANUAL: confirm the admin sees it in the dashboard (scenario 13).",
      ],
    );
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
    let expiredOk = true;
    if (process.env.POLICY_FILE) {
      const draft = JSON.parse(readFileSync(process.env.POLICY_FILE, "utf8").replace(/<sha256[^>]*>/g, "0".repeat(64)));
      const gid = draft.groups[0].gid;
      draft.enrollmentKeys.push({ id: `acc-expired-${RUN}`, gid, sha256: "f".repeat(64), guest: true, expiresAt: "2020-01-01T00:00:00Z" });
      const r = await request(URL_, "POST", "/admin/v1/explain", ADMIN, { policy: draft, as: { key: `acc-expired-${RUN}` }, op: "r", resource: { kind: "stream", id: `relaycast:channel/${localChannel}` } });
      // Enabled, so it must really answer: a successful explain that denies with key_expired.
      expiredOk = r.status === 200 && r.body?.decision === "deny" && r.body?.reason === "key_expired";
      notes.push(`guest key with expiresAt in the past (draft policy, via explain): ${r.status} ${r.body?.decision ?? ""} (${r.body?.reason ?? r.body?.error?.code ?? r.body?.error ?? ""})`);
    } else notes.push("expired guest key: SKIPPED (set POLICY_FILE to check it against a draft policy; the deployment policy has no guest key)");
    notes.push("A revoked or expired guest key ending live tokens is covered by relaygate's unit tests (test/app.test.ts, enrollment key lifecycle).");
    record(10, "unenrolled key refused; expired guest key can't register", bad.status === 401 && expiredOk ? "PASS" : "FAIL", notes);
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
      // Bring relaygate back whatever happens once the down hook starts: in finally, and on exit as a fallback.
      let upDone = false;
      const bringUp = () => {
        if (upDone) return;
        execSync(process.env.RG_UP_CMD!, { stdio: "inherit" });
        upDone = true;
      };
      process.once("exit", bringUp);
      try {
        execSync(process.env.RG_DOWN_CMD, { stdio: "inherit" });
        await sleep(5000);
        const down = await localA.call("POST", "/v1/dm", { to: pitA, text: "while down" });
        notes.push(`request while relaygate is down: ${down.status} ${down.body?.error ?? ""} (anything but 2xx; nothing can reach upstream without relaygate)`);
        pass &&= !ok(down.status);
      } finally {
        bringUp();
      }
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
    // Whatever happens after the flip, the original policy is restored before the driver moves on or exits.
    let restoredOnce = false;
    const restore = () => {
      if (restoredOnce) return;
      // Marked done only once the command succeeds, so the exit handler retries a failed restore.
      execSync(process.env.RG_POLICY_RESTORE_CMD!, { stdio: "inherit" });
      restoredOnce = true;
    };
    process.once("exit", restore);
    let flipped: string | undefined, allowed: any, restored: string | undefined, deniedAgain: any;
    try {
      execSync(process.env.RG_POLICY_FLIP_CMD, { stdio: "inherit" });
      flipped = await waitVersion((v) => v !== undefined && v !== before);
      const h1 = await auditHead();
      await command(localA, pitA, { acc: "reply", run: `${RUN}f`, to: localA.name });
      allowed = (await waitFor(pitA, h1, ["dm.send"])).find((r) => r.action === "dm.send");
    } finally {
      restore();
    }
    restored = await waitVersion((v) => v === before);
    const h2 = await auditHead();
    await command(localA, pitA, { acc: "reply", run: `${RUN}r`, to: localA.name });
    deniedAgain = (await waitFor(pitA, h2, ["dm.send"])).find((r) => r.action === "dm.send");
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

/**
 * Every place the outside can read, searched for this run's canary prefix. A read that fails, or doesn't have the
 * expected shape, is reported as missing coverage, never as "no canary".
 */
async function canarySweep(outside: Gate[], channel: string, session: string | undefined, frames: string[]): Promise<{ hits: string[]; gaps: string[] }> {
  const hits: string[] = [];
  const gaps: string[] = [];
  const has = (v: unknown) => JSON.stringify(v ?? "").includes(CANARY_PREFIX);
  const probe = async (label: string, r: Promise<{ status: number; body: any }>, shape: (body: any) => boolean) => {
    const res = await r;
    if (res.status < 200 || res.status >= 300 || !shape(res.body)) {
      gaps.push(`${label} (${res.status})`);
      return undefined;
    }
    if (has(res.body)) hits.push(label);
    return res;
  };
  const isArray = (b: any) => Array.isArray(dataOf({ status: 200, body: b }));
  for (const g of outside) {
    const convs = await probe(`${g.name} DM list`, g.call("GET", "/v1/dm/conversations"), isArray);
    for (const c of convs ? dataOf(convs) : []) {
      await probe(`${g.name} DM ${c.id}`, g.call("GET", `/v1/dm/${encodeURIComponent(c.id)}/messages?limit=100`), isArray);
    }
    await probe(`${g.name} inbox`, g.call("GET", "/v1/inbox"), (b) => typeof dataOf({ status: 200, body: b }) === "object");
    await probe(`${g.name} #${channel}`, g.call("GET", `/v1/channels/${channel}/messages`), isArray);
    await probe(`${g.name} search`, g.call("GET", `/v1/search?q=${encodeURIComponent(CANARY_PREFIX)}`), isArray);
    if (session) {
      await probe(`${g.name} session ${session} events`, g.call("GET", `/sessions/v1/sessions/${session}/events`), (b) => b && typeof b === "object");
      await probe(`${g.name} session ${session} turns`, g.call("GET", `/sessions/v1/sessions/${session}/turns`), (b) => b && typeof b === "object");
    }
  }
  if (frames.some((f) => f.includes(CANARY_PREFIX))) hits.push("realtime frames");
  return { hits, gaps };
}

main().catch((error) => {
  console.error(`acceptance driver error: ${(error as Error).message}`);
  process.exit(2);
});
