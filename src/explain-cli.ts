/**
 * relaygate explain: may X do op on Y, and why. Offline; reads a policy file (live or draft) and, optionally,
 * relaygate's database for registered agents and streams.
 *
 *   relaygate-explain --policy policy.json --as key:vendor-guest --op w --stream relaycast:channel/collab-x
 *   relaygate-explain --policy draft.json --cases cases.json        # exits 1 if any case fails
 *
 * --as is agent:<name> (needs --db), key:<id>[:<name>], or gid:<gid>[,<supplementary>...].
 */
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { explain, runCases, type Explanation, type Subject } from "./explain.js";
import { loadPolicyFile } from "./policy.js";
import { Store } from "./store.js";

function usage(message?: string): never {
  if (message) console.error(message);
  console.error(
    "usage: relaygate-explain --policy <file> [--db <file>] [--json] (--as <subject> --op r|w --stream <id> | --cases <file>)\n" +
      "  subject: agent:<name> | key:<id>[:<name>] | gid:<gid>[,<gid>...]",
  );
  process.exit(2);
}

export function parseSubject(text: string): Subject {
  const [kind, ...rest] = text.split(":");
  const value = rest.join(":");
  if (!value) usage(`bad --as ${text}`);
  if (kind === "agent") return { agent: value };
  if (kind === "key") {
    const [key, ...name] = value.split(":");
    return name.length ? { key: key!, name: name.join(":") } : { key: key! };
  }
  if (kind === "gid") {
    const gids = value.split(",").map(Number);
    if (gids.some((g) => !Number.isInteger(g) || g < 0)) usage(`bad --as ${text}`);
    return { gid: gids[0]!, groups: gids.slice(1) };
  }
  usage(`bad --as ${text}`);
}

function print(e: Explanation): void {
  console.log(`${e.decision.toUpperCase()}  ${e.summary}`);
  for (const s of e.steps) console.log(`  ${s.step.padEnd(10)} ${s.detail}`);
  console.log(`  reason     ${e.reason}`);
}

const { values } = parseArgs({
  options: {
    policy: { type: "string" },
    db: { type: "string" },
    as: { type: "string" },
    op: { type: "string" },
    stream: { type: "string" },
    cases: { type: "string" },
    json: { type: "boolean", default: false },
  },
});
if (!values.policy) usage("--policy is required");

let policy;
try {
  policy = loadPolicyFile(values.policy);
} catch (error) {
  console.error(`policy ${values.policy} is invalid: ${(error as Error).message}`);
  process.exit(2);
}
const store = values.db ? new Store(values.db, { readOnly: true }) : undefined;

if (values.cases) {
  const raw = JSON.parse(readFileSync(values.cases, "utf8"));
  const results = runCases(policy, store, Array.isArray(raw) ? raw : raw.cases);
  const failed = results.filter((r) => !r.pass);
  if (values.json) console.log(JSON.stringify({ passed: results.length - failed.length, failed: failed.length, results }, null, 2));
  else {
    for (const r of results) {
      const want = `${r.case.expect}${r.case.classified === undefined ? "" : r.case.classified ? "+classified" : "+unclassified"}`;
      const got = `${r.got.decision}${r.got.classified ? "+classified" : ""}`;
      console.log(`${r.pass ? "pass" : "FAIL"}  ${r.case.note ?? `${JSON.stringify(r.case.as)} ${r.case.op} ${r.case.resource.id}`}  (want ${want}, got ${got})`);
      if (!r.pass) for (const s of r.got.steps) console.log(`        ${s.step.padEnd(10)} ${s.detail}`);
    }
    console.log(`${results.length - failed.length} passed, ${failed.length} failed`);
  }
  store?.close();
  process.exit(failed.length > 0 ? 1 : 0);
}

if (!values.as || !values.stream || (values.op !== "r" && values.op !== "w")) usage();
const e = explain(policy, store, { as: parseSubject(values.as), op: values.op, resource: { kind: "stream", id: values.stream } });
if (values.json) console.log(JSON.stringify(e, null, 2));
else print(e);
store?.close();
process.exit(e.decision === "allow" ? 0 : 1);
