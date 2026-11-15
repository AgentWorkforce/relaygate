import { statSync } from "node:fs";
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { classifierFromPolicy, type Classifier } from "./classifier.js";
import { loadPolicyFile, type Policy } from "./policy.js";
import { Store } from "./store.js";

const policyPath = process.env.RELAYGATE_POLICY;
if (!policyPath) {
  console.error("RELAYGATE_POLICY must point at the operator policy JSON file");
  process.exit(1);
}
const dbPath = process.env.RELAYGATE_DB ?? "/data/relaygate.db";
const port = Number(process.env.PORT ?? 8080);
const reloadMs = Number(process.env.RELAYGATE_POLICY_RELOAD_MS ?? 5000);

let policy: Policy = loadPolicyFile(policyPath);
let classifier: Classifier = classifierFromPolicy(policy);
let mtime = statSync(policyPath).mtimeMs;

// Keep the last good policy if a new one doesn't parse, so a bad edit never opens the gate.
setInterval(() => {
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

const store = new Store(dbPath);
const app = createApp({ store, policy: () => policy, classifier: () => classifier });

const server = serve({ fetch: app.fetch, port }, (info) => {
  console.log(JSON.stringify({ msg: "relaygate listening", port: info.port, model_classifier: policy.classifier.model.enabled }));
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close();
    store.close();
    process.exit(0);
  });
}
