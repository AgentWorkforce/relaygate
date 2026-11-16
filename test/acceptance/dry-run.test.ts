/**
 * Runs the real acceptance driver (scripts/acceptance/run.ts) as a subprocess against an in-process relaygate with
 * the double-pit example policy, in front of in-memory Relaycast and Sessions stand-ins. The stand-in Relaycast has no
 * realtime socket, so realtime coverage is marked optional here (a real deployment must show the control delivery). Proves the harness itself
 * works end to end before it is pointed at a real deployment.
 */
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import { afterAll, describe, expect, it } from "vitest";
import { createApp, type Deps } from "../../src/app.js";
import { ChainClassifier, RuleClassifier } from "../../src/classifier.js";
import { parsePolicy } from "../../src/policy.js";
import { NodeSockets } from "../../src/realtime.js";
import { RelaycastUpstream } from "../../src/relaycast.js";
import { SecretBox, sha256, Store } from "../../src/store.js";
import { fakeRelaycast, WORKSPACE_KEY } from "../fakes/relaycast.js";
import { fakeSessionsServer } from "./fake-sessions.js";

const KEYS = { local: "enroll-local-dryrun-000000000000", pit: "enroll-pit-dryrun-00000000000000", "slack-bridge": "enroll-bridge-dryrun-0000000000" };
const ADMIN = "admin-token-dryrun-000000000000";
const closers: Array<() => void> = [];

const DEPLOYMENT_VARS = /^(RG_|SESSIONS_READ_REFRESH_CMD$|INSIDE_LOGS_CMD$|INSIDE_AGENTS$|RELAYCAST_DIRECT_URL$|DIRECT_SESSIONS_READ_URL$|OUTSIDE_|INSIDE_SESSIONS_|ADMIN_TOKEN$|POLICY_FILE$)/;
function withoutDeploymentHooks(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([k]) => !DEPLOYMENT_VARS.test(k)));
}
afterAll(() => closers.forEach((f) => f()));

const listen = async (server: Server) => {
  await new Promise<void>((r) => (server.listening ? r() : server.once("listening", () => r())));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
};

describe("acceptance driver dry run", { timeout: 300_000 }, () => {
  it("passes every automated scenario against the double-pit policy", async () => {
    const raw = JSON.parse(readFileSync(new URL("../../examples/policy.double-pit.json", import.meta.url), "utf8"));
    for (const k of raw.enrollmentKeys) k.sha256 = sha256(KEYS[k.id as keyof typeof KEYS]);
    raw.classifier.model.enabled = false;
    const policyFile = join(mkdtempSync(join(tmpdir(), "rg-acc-")), "policy.json");
    writeFileSync(policyFile, JSON.stringify(raw));
    const policy = parsePolicy(raw);

    const rc = fakeRelaycast();
    const rcServer = serve({ fetch: rc.app.fetch, port: 0 }) as unknown as Server;
    const rcUrl = await listen(rcServer);
    const ss = fakeSessionsServer().listen(0);
    const ssUrl = await listen(ss);
    const store = new Store(":memory:");
    const relaycast = new RelaycastUpstream({ url: rcUrl, workspaceKey: WORKSPACE_KEY, box: new SecretBox("d".repeat(32)) }, store);
    const classifier = new ChainClassifier([new RuleClassifier(policy.classifier.rules)]);
    const deps: Deps = { store, policy: () => policy, classifier: () => classifier, relaycast, adminToken: ADMIN, sessions: { uploadUrl: ssUrl, readUrl: ssUrl, token: "svc" } };
    const sockets = new NodeSockets(deps, relaycast, 60_000);
    deps.onTokensRevoked = () => sockets.revalidate();
    const gate = serve({ fetch: createApp(deps).fetch, port: 0 }) as unknown as Server;
    const gateUrl = await listen(gate);
    sockets.attach(gate);
    closers.push(() => sockets.close(), () => gate.close(), () => rcServer.close(), () => ss.close());

    const out = await new Promise<{ code: number | null; text: string }>((resolve) => {
      const child = spawn(process.execPath, ["--import", "tsx", "scripts/acceptance/run.ts"], {
        // Never inherit the operator's deployment hooks: this run targets in-process stand-ins only.
        env: { ...withoutDeploymentHooks(process.env), RELAYGATE_URL: gateUrl, OUTSIDE_KEY: KEYS.local, INSIDE_KEY: KEYS.pit, ADMIN_TOKEN: ADMIN, POLICY_FILE: policyFile, RUN_ID: "dry-1_a", SESSIONS_ORG_ID: "org-dry", SESSIONS_WORKSPACE_ID: "ws-dry", ACCEPTANCE_REALTIME: "optional",
          // The stand-in Sessions accepts any token and is reachable directly: scenario 14 must catch that bypass.
          OUTSIDE_SESSIONS_READ: "rth_at_read_dry", DIRECT_SESSIONS_READ_URL: ssUrl },
      });
      let text = "";
      child.stdout.on("data", (d) => (text += d));
      child.stderr.on("data", (d) => (text += d));
      child.on("close", (code) => resolve({ code, text }));
    });
    const verdicts = Object.fromEntries([...out.text.matchAll(/^\[(PASS|FAIL|SKIP|MANUAL)\] (\d+)\./gm)].map((m) => [m[2], m[1]]));
    if (out.code !== 0) console.log(out.text);
    expect(verdicts).toMatchObject({ "1": "PASS", "2": "PASS", "3": "PASS", "4": "PASS", "5": "PASS", "6": "PASS", "7": "PASS", "8": "PASS", "9": "PASS", "10": "PASS", "13": "MANUAL", "14": "FAIL", "15": "SKIP", "16": "PASS" });
    expect(out.text).toMatch(/INSIDE SESSION READABLE WITHOUT relaygate/);
    // The only failure is the bypass the stand-in deliberately allows.
    expect(out.code).toBe(1);
  });
});

describe("inside test agent", () => {
  it("ignores DMs sent before it started, so a restarted pod never replays earlier runs", async () => {
    const { sentSince } = await import("../../scripts/acceptance/agent.ts");
    const start = Date.parse("2026-11-15T12:00:00Z");
    expect(sentSince({ created_at: "2026-11-15T11:00:00Z" }, start)).toBe(false);
    expect(sentSince({ created_at: "2026-11-15T12:00:01Z" }, start)).toBe(true);
    expect(sentSince({}, start)).toBe(true);
  });
});

