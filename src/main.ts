import { statSync } from "node:fs";
import { serve } from "@hono/node-server";
import { createApp, sweepGuestKeys } from "./app.js";
import { classifierFromPolicy, type Classifier } from "./classifier.js";
import { loadPolicyFile, type Policy } from "./policy.js";
import { NodeSockets } from "./realtime.js";
import { RelaycastUpstream } from "./relaycast.js";
import { routeSessionsHosts } from "./sessions.js";
import { ControlAuth } from "./control.js";
import { SecretBox, Store } from "./store.js";

const policyPath = process.env.RELAYGATE_POLICY;
if (!policyPath) {
  console.error("RELAYGATE_POLICY must point at the operator policy JSON file");
  process.exit(1);
}
const dbPath = process.env.RELAYGATE_DB ?? "/data/relaygate.db";
const port = Number(process.env.PORT ?? 8080);
const reloadMs = Number(process.env.RELAYGATE_POLICY_RELOAD_MS ?? 5000);

const store = new Store(dbPath);
let policy: Policy = loadPolicyFile(policyPath);
let classifier: Classifier = classifierFromPolicy(policy);
let mtime = statSync(policyPath).mtimeMs;

// Keep the last good policy if a new one doesn't parse, so a bad edit never opens the gate.
setInterval(() => {
  // Guest keys that were revoked or have expired end their tokens even if no one calls with them.
  const ended = sweepGuestKeys(store, policy, Date.now());
  if (ended.length > 0) {
    console.log(JSON.stringify({ msg: "guest tokens ended", count: ended.length }));
    sockets?.revalidate();
  }
  try {
    const m = statSync(policyPath).mtimeMs;
    if (m === mtime) return;
    const next = loadPolicyFile(policyPath);
    policy = next;
    classifier = classifierFromPolicy(next);
    mtime = m;
    console.log(JSON.stringify({ msg: "policy reloaded", groups: next.groups.length, keys: next.enrollmentKeys.length }));
  } catch (error) {
    console.error(JSON.stringify({ msg: "policy reload failed; keeping the previous policy", error: (error as Error).message }));
  }
}, reloadMs).unref();

const adminToken = process.env.RELAYGATE_ADMIN_TOKEN || undefined;
if (adminToken !== undefined && adminToken.length < 24) {
  console.error("RELAYGATE_ADMIN_TOKEN must be at least 24 characters");
  process.exit(1);
}
// The Relaycast proxy is on when RELAYCAST_URL is set; it needs the workspace key and a secret to seal agent tokens.
let relaycast: RelaycastUpstream | undefined;
if (process.env.RELAYCAST_URL) {
  const workspaceKey = process.env.RELAYCAST_WORKSPACE_KEY;
  const secret = process.env.RELAYGATE_SECRET;
  if (!workspaceKey || !secret || secret.length < 32) {
    console.error("RELAYCAST_URL needs RELAYCAST_WORKSPACE_KEY and RELAYGATE_SECRET (at least 32 characters)");
    process.exit(1);
  }
  relaycast = new RelaycastUpstream({ url: process.env.RELAYCAST_URL, workspaceKey, box: new SecretBox(secret) }, store);
}
// The Sessions proxy is on when SESSIONS_URL (or SESSIONS_UPLOAD_URL and SESSIONS_READ_URL) is set. relaygate
// forwards each caller's own Sessions credential; SESSIONS_TOKEN is an optional fallback for callers that send none.
let sessions: import("./sessions.js").SessionsConfig | undefined;
const uploadUrl = process.env.SESSIONS_UPLOAD_URL || process.env.SESSIONS_URL;
const readUrl = process.env.SESSIONS_READ_URL || process.env.SESSIONS_URL;
if (uploadUrl || readUrl) {
  if (!uploadUrl || !readUrl) {
    console.error("set SESSIONS_URL, or both SESSIONS_UPLOAD_URL and SESSIONS_READ_URL");
    process.exit(1);
  }
  const hosts = (process.env.SESSIONS_HOSTS ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  sessions = { uploadUrl, readUrl, token: process.env.SESSIONS_TOKEN || undefined, hosts, internalSecret: process.env.SESSIONS_INTERNAL_SECRET || undefined };
}
// relay-control principals (desktop device tokens, dashboard read tokens) are on when the introspection URL is set.
let control: ControlAuth | undefined;
if (process.env.RELAYCONTROL_INTROSPECT_URL) {
  const secret = process.env.RELAYCONTROL_INTROSPECT_SECRET;
  const audience = process.env.SESSION_INGEST_AUDIENCE;
  if (!secret || !audience) {
    console.error("RELAYCONTROL_INTROSPECT_URL needs RELAYCONTROL_INTROSPECT_SECRET and SESSION_INGEST_AUDIENCE");
    process.exit(1);
  }
  control = new ControlAuth({ introspectUrl: process.env.RELAYCONTROL_INTROSPECT_URL, introspectSecret: secret, audience }, store);
}
let sockets: NodeSockets | undefined;
const deps = { store, policy: () => policy, classifier: () => classifier, adminToken, relaycast, sessions, control, onTokensRevoked: () => sockets?.revalidate() };
const app = createApp(deps);

const fetchFn = sessions?.hosts?.length ? routeSessionsHosts(app.fetch, sessions.hosts) : app.fetch;
const server = serve({ fetch: fetchFn, port }, (info) => {
  console.log(JSON.stringify({ msg: "relaygate listening", port: info.port, model_classifier: policy.classifier.model.enabled, relaycast: !!relaycast, sessions: !!sessions, sessions_hosts: sessions?.hosts ?? [], control_principals: !!control }));
});
if (relaycast) {
  sockets = new NodeSockets(deps, relaycast);
  sockets.attach(server as unknown as import("node:http").Server);
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    sockets?.close();
    server.close();
    store.close();
    process.exit(0);
  });
}
