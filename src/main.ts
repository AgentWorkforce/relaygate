import { serve } from "@hono/node-server";
import { createApp, sweepGuestKeys } from "./app.js";
import { classifierFromPolicy, type Classifier } from "./classifier.js";
import { policyVersion, type Policy } from "./policy.js";
import { ControlPolicySource, FilePolicySource, type PolicySource } from "./policy-source.js";
import { NodeSockets } from "./realtime.js";
import { RelaycastUpstream } from "./relaycast.js";
import { routeSessionsHosts, sessionsAtRoot } from "./sessions.js";
import { ControlAuth } from "./control.js";
import { SecretBox, Store } from "./store.js";

const policyPath = process.env.RELAYGATE_POLICY;
const policyUrl = process.env.RELAYCONTROL_POLICY_URL;
if (!policyPath === !policyUrl) {
  console.error("set exactly one policy source: RELAYGATE_POLICY (a JSON file) or RELAYCONTROL_POLICY_URL (pulled from relay-control)");
  process.exit(1);
}
const policySecret = process.env.RELAYCONTROL_POLICY_SECRET ?? "";
if (policyUrl && policySecret.length < 32) {
  console.error("RELAYCONTROL_POLICY_URL needs RELAYCONTROL_POLICY_SECRET (at least 32 characters)");
  process.exit(1);
}
const dbPath = process.env.RELAYGATE_DB ?? "/data/relaygate.db";
const port = Number(process.env.PORT ?? 8080);
const reloadMs = Number(process.env.RELAYGATE_POLICY_RELOAD_MS ?? 5000);

const store = new Store(dbPath);
// A file must parse at startup. relay-control may be down: relaygate starts from its cached copy, or refuses
// everything (503) until the first good pull.
const source: PolicySource = policyUrl ? new ControlPolicySource({ url: policyUrl, secret: policySecret }, store) : new FilePolicySource(policyPath!);
const classifiers = new WeakMap<Policy, Classifier>();
const policy = () => source.current();
const classifier = () => {
  const p = policy();
  let c = classifiers.get(p);
  if (!c) classifiers.set(p, (c = classifierFromPolicy(p)));
  return c;
};

const sweep = () => {
  let p: Policy;
  try {
    p = policy();
  } catch {
    return;
  }
  // Guest keys that were revoked or have expired end their tokens even if no one calls with them.
  const ended = sweepGuestKeys(store, p, Date.now());
  if (ended.length > 0) {
    console.log(JSON.stringify({ msg: "guest tokens ended", count: ended.length }));
    sockets?.revalidate();
  }
};
let refreshing = false;
const tick = async () => {
  if (refreshing) return;
  refreshing = true;
  try {
    const before = source.status().lastRejected?.at;
    if (await source.refresh()) {
      const p = policy();
      console.log(JSON.stringify({ msg: "policy applied", version: policyVersion(p), groups: p.groups.length, keys: p.enrollmentKeys.length }));
    } else if (source.status().lastRejected && source.status().lastRejected?.at !== before) {
      // Keep the last good policy if a new one doesn't verify or parse, so a bad edit never opens the gate.
      console.error(JSON.stringify({ msg: "policy rejected; keeping the policy in force", ...source.status().lastRejected }));
    }
    sweep();
  } finally {
    refreshing = false;
  }
};
setInterval(() => void tick(), reloadMs).unref();
if (policyUrl) void tick();

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
  sessions = { uploadUrl, readUrl, token: process.env.SESSIONS_TOKEN || undefined, hosts, internalSecret: process.env.SESSIONS_INTERNAL_SECRET || undefined, corsOrigins: (process.env.SESSIONS_CORS_ORIGINS ?? "").split(",").map((o) => o.trim()).filter(Boolean) };
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
const deps = { store, policy, classifier, policyStatus: () => source.status(), adminToken, relaycast, sessions, control, onTokensRevoked: () => sockets?.revalidate() };
const app = createApp(deps);

const fetchFn = sessions?.hosts?.length ? routeSessionsHosts(app.fetch, sessions.hosts) : app.fetch;
const server = serve({ fetch: fetchFn, port }, (info) => {
  console.log(JSON.stringify({ msg: "relaygate listening", port: info.port, policy_source: source.status().source, relaycast: !!relaycast, sessions: !!sessions, sessions_hosts: sessions?.hosts ?? [], control_principals: !!control }));
});
// An internal listener serving Sessions at its root, so a control plane that requires a bare-origin Sessions URL can
// point at relaygate (and mint read tokens through it). Keep it off any public route.
const sessionsPort = process.env.SESSIONS_PORT ? Number(process.env.SESSIONS_PORT) : undefined;
let sessionsServer: ReturnType<typeof serve> | undefined;
if (sessions && sessionsPort) {
  sessionsServer = serve({ fetch: sessionsAtRoot(app.fetch), port: sessionsPort }, (info) => {
    console.log(JSON.stringify({ msg: "relaygate sessions listener", port: info.port }));
  });
}
if (relaycast) {
  sockets = new NodeSockets(deps, relaycast);
  sockets.attach(server as unknown as import("node:http").Server);
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    sockets?.close();
    sessionsServer?.close();
    server.close();
    store.close();
    process.exit(0);
  });
}
