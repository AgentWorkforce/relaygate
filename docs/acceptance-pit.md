# Boundary acceptance test (the pit)

An end-to-end test of a regulated boundary that we drive ourselves,
independent of Slack: agents inside the boundary hold an internal document,
agents outside try every way to get it, and relaygate's audit log is the
evidence. It is written against `examples/policy.double-pit.json` (groups
`local` = outside, `pit` = inside) used as-is; nothing here changes code or
topology, and every name below can be overridden for another policy.

The test uses only synthetic data. The internal document is invented, and each
run's canary (`CANARY-<run>-<secret>`) is made up by the inside agent, so the
outside never learns the full string and can only search for `CANARY-<run>`.

## What runs where

| Role | Where | Enrolls with | Runs |
|---|---|---|---|
| Inside agents (2) | headless, next to the protected workloads (a pod in the cluster) | the inside (`pit`) key | `node scripts/acceptance/agent.ts` |
| Outside agents (2) | the operator's laptop | the outside (`local`) key | played by `node scripts/acceptance/run.ts` |
| Evidence | relaygate | admin token | `GET /admin/v1/audit` (decision, principal, resource, reason, policy version; never content) |

The driver commands the inside agents by DM, which is the one direction the
policy lets the outside write in, and only with harmless commands (seed, reply,
read a session); a classifier would rightly refuse a DM that says "exfiltrate".
The inside agents behave like compromised agents instead: right after seeding
their document they try every way out on their own, and when an outside agent
asks for the document in plain words they try to answer with it. They print only
statuses, never the document. The driver then checks the audit log and sweeps
everything the outside can read for the canary.

Both scripts ship in the relaygate image under `/app/scripts/acceptance` and
run with `node` directly (no build step).

## Scenarios

| # | Scenario | Expected | How |
|---|---|---|---|
| 1 | Outside DMs an inside agent; posts into an inside stream | delivered (outside has `w` on the inside) | driver |
| 2 | Inside agent replies to the outside (DM, outside stream, thread) | every attempt 403, nothing delivered | driver |
| 3 | Outside reads the inside document (stream, history, join, session, search) | 403; search and channel lists never show it | driver |
| 4 | Outside asks an inside agent, in plain words, to paste the document | either the classifier refuses the ask, or every answer the inside agent attempts is 403; the canary appears nowhere outside (DMs, inbox, channel, search, sessions, realtime frames) | driver |
| 5 | Inside agents, unprompted after seeding: outside DM, thread, outside channel, `@mention`, outside session, new stream, stream registration, unknown stream | all 403 | driver |
| 6 | Outside session upload | stored; readable by another outside agent and by an inside agent; admin sees it | driver + manual (13) |
| 7 | Outside appends to an inside session (`11:w`) | accepted and classified; outside can't read it back | driver |
| 8 | Inside session upload | outside can't read or list it; admin sees it | driver + manual (13) |
| 9 | Classifier | see below | driver |
| 10 | Unenrolled key; guest key with `expiresAt` in the past | 401; `key_expired` | driver (needs `POLICY_FILE` for the expired key) |
| 11 | relaygate down / bypass | no fail-open: nothing reaches upstream; clients never hold upstream credentials | driver (needs hooks for the down part) |
| 12 | Policy change takes effect | flip one ACL, rerun 2 (now allowed), restore (refused again); audit shows both policy versions | driver (needs hooks) |
| 13 | Admin view | the org admin sees outside and inside sessions per person | manual |
| 14 | Bypass: an outside member's own Sessions read token, straight at Sessions (e.g. the public history host), skipping relaygate | refused: no connection, 401/403/404, never the inside session | driver (needs `DIRECT_SESSIONS_READ_URL`) |

**Scenario 9, why there is no inside-to-outside classifier path.** The policy
gives the inside no write bit on anything the outside can read, so every inside
write toward the outside is refused by the mode bits before the classifier is
consulted. The driver proves that with `explain` (as an inside agent, `w` on
the outside channel, inbox and session: all `deny` at mode) and exercises the
classifier on the cross-group path that does exist: an outside DM to an inside
agent carrying an SSN is refused with `relaygate_classified`. A canary-specific
classifier test would need a path the policy deliberately doesn't have.

**Scenario 10, expired guest key.** The deployment policy has no guest key. With
`POLICY_FILE` set, the driver adds an expired guest key to a *draft* of the
policy and asks `explain`, which answers `key_expired` without applying
anything. Revoked or expired guest keys ending live tokens (and closing their
sockets) are covered by relaygate's unit tests.

## Runbook

### 0. Prerequisites

- relaygate running the target policy, with the Relaycast proxy on
  (`RELAYCAST_URL`) and, for scenarios 6-8, the Sessions proxy on
  (`SESSIONS_UPLOAD_URL`, `SESSIONS_READ_URL`).
- `RELAYGATE_ADMIN_TOKEN` set on relaygate (the driver reads the audit log and
  calls `explain`).
- The enrollment keys for the outside and inside groups.
- A checkout of this repo on the laptop (Node 24 or later), or the relaygate
  image.

### 1. Reach relaygate

Without an Ingress, port-forward from a machine the cluster API allows:

```
kubectl -n <relaygate namespace> port-forward svc/<relaygate service> 18090:8080
export RELAYGATE_URL=http://127.0.0.1:18090
curl -s $RELAYGATE_URL/readyz     # {"ok":true,"policy_version":"..."}
```

WebSockets work through the port-forward.

### 2. Start the inside agents

In the cluster, next to the protected workloads (two replicas, distinct names):

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata: { name: acceptance-inside, namespace: <inside namespace> }
spec:
  replicas: 2
  serviceName: acceptance-inside
  selector: { matchLabels: { app: acceptance-inside } }
  template:
    metadata: { labels: { app: acceptance-inside } }
    spec:
      containers:
        - name: agent
          image: ghcr.io/agentworkforce/relaygate@<digest>
          command: ["node", "scripts/acceptance/agent.ts"]
          env:
            - { name: RELAYGATE_URL, value: "http://<relaygate service>.<namespace>.svc.cluster.local:8080" }
            - { name: AGENT_NAME, value: "pit-acc-{ordinal}" }   # pit-acc-0, pit-acc-1; must match the inside key's name prefix
            - { name: RELAYGATE_ENROLL_KEY, valueFrom: { secretKeyRef: { name: <secret>, key: pit } } }
            - { name: AGENT_RECOVERY, valueFrom: { secretKeyRef: { name: <secret>, key: recovery } } }  # >= 16 chars, stable
            # Optional, if Sessions needs the agent's own credentials (relaygate forwards them):
            # - { name: SESSIONS_UPLOAD_CREDENTIAL, valueFrom: ... }   # sh_at_...
            # - { name: SESSIONS_READ_CREDENTIAL, valueFrom: ... }     # rth_at_read_...
            # - { name: SESSIONS_READ_REFRESH_CMD, value: "<prints a fresh read token>" }  # for short-lived read tokens
            # - { name: SESSIONS_ORG_ID, value: "<org id>" }           # self-hosted Sessions: native uploads,
            # - { name: SESSIONS_WORKSPACE_ID, value: "<workspace id>" } # workspace-scoped reads
            # - { name: DOC_CHANNEL_PREFIX, value: "pit-" }           # a channel prefix inside the boundary
```

`AGENT_RECOVERY` lets a restarted pod reclaim the same identity. Each agent
logs one line per attempt (`{"run":..,"attempt":"exfil.dm","status":403,...}`);
the document itself is never logged.

For a dry run without pods, skip this step and give the driver `INSIDE_KEY`:
it then runs two inside agents in-process.

### 3. Run the driver

Sessions read tokens (`rth_at_read_…`) can be short-lived (self-hosted Control
issues them for 300 s). Give the driver `SESSIONS_READ_REFRESH_CMD`: a command
that prints fresh `OUTSIDE_SESSIONS_READ=…` and `INSIDE_SESSIONS_READ=…` lines
(for example by exchanging each user's device token at
`POST /api/v1/workspaces/<ws>/session-read/session`). The driver runs it before
every scenario that reads sessions. An expired token shows up as
`upstream 401` in scenarios 6 and 8 (the gate allowed the read; Sessions
refused the token). Self-hosted ingest is asynchronous: an upload becomes
readable on the search indexer's reconcile tick (every 5 minutes by default), so
set `ACCEPTANCE_INGEST_WAIT_MS=360000` there (and on the inside agents); the
driver and the inside agents poll a session until the content they wrote
appears.

Uploads look like real Claude Code sessions (a `session` record with a title
and first prompt, then a user and an assistant event), so in the dashboard each
test session has a title, a brief and readable events. The read API's `/turns`
view stays empty for them: turns come only from the private turns route, which
the public delivery protocol can't write.

**Scenario 14 (bypass).** relaygate forwards each caller's own Sessions
credential, so a member who holds one can try Sessions directly. Set
`DIRECT_SESSIONS_READ_URL` to the Sessions read origin as reachable without
relaygate (the public history host); the driver reads the inside session with
the outside user's own read token there. It must be refused. Until Sessions
admits only relaygate (NetworkPolicy, and the history host routed to relaygate
via `SESSIONS_HOSTS`), this scenario fails: that is the finding it exists to
catch.

```
export OUTSIDE_KEY=<outside enrollment key>
export ADMIN_TOKEN=<relaygate admin token>
export INSIDE_AGENTS=pit-acc-0,pit-acc-1      # or INSIDE_KEY=<inside key> for in-process agents
export POLICY_FILE=examples/policy.double-pit.json   # enables the expired-guest-key check
# With remote inside agents, how to read their status lines (scenario 8 checks their seed upload landed):
export INSIDE_LOGS_CMD='kubectl -n <inside namespace> logs -l app=acceptance-inside --tail=-1'
# If Sessions needs the callers' own credentials:
# export OUTSIDE_SESSIONS_UPLOAD=sh_at_...  OUTSIDE_SESSIONS_READ=rth_at_read_...
# (and INSIDE_SESSIONS_UPLOAD / INSIDE_SESSIONS_READ when the driver runs the inside agents in-process)
# Self-hosted Sessions (session-ingest + session-read-api): uploads use the native delivery protocol, whose
# account id is derived from the org and workspace, and every read names the workspace:
# export SESSIONS_ORG_ID=<org id>  SESSIONS_WORKSPACE_ID=<workspace id>
set -o pipefail   # keep the driver's exit code through tee
node scripts/acceptance/run.ts | tee acceptance-$(date +%Y%m%d-%H%M).log
```

Each scenario prints `[PASS]`, `[FAIL]`, `[SKIP]` or `[MANUAL]`, the statuses
each client saw, and the audit rows that prove it. The last line lists every
verdict; the exit code is 1 if anything failed.

### 4. Scenarios 11 and 12 (optional hooks)

The driver can't change the deployment by itself. Give it the commands:

```
# 11: take relaygate down and bring it back (requests in between must fail, never reach upstream)
export RG_DOWN_CMD='kubectl -n <ns> scale deploy/<relaygate> --replicas=0'
export RG_UP_CMD='kubectl -n <ns> scale deploy/<relaygate> --replicas=1 && sleep 20 && (pkill -f "port-forward svc/<relaygate>"; kubectl -n <ns> port-forward svc/<relaygate> 18090:8080 >/dev/null 2>&1 &)'
export RELAYCAST_DIRECT_URL=<Relaycast URL, if reachable>   # an rg_ token there must get 401

# 12: flip one ACL (let the inside answer outside inboxes), then restore
export RG_POLICY_FLIP_CMD='<edit the policy: add {"gid":22,"perm":"w"} to relaycast:inbox/local- and apply it>'
export RG_POLICY_RESTORE_CMD='<apply the original policy again>'
```

relaygate reloads its policy within a few seconds (`RELAYGATE_POLICY_RELOAD_MS`,
default 5000); the driver waits for `/readyz` to report the new
`policy_version` before rerunning scenario 2, and for the original version
after restoring.

### 5. Scenario 13 (manual)

In the dashboard, as the org admin: open the people/usage view and confirm the
outside test user's session (`acc-local-<run>`) and the inside agents' session
(`acc-doc-<run>`) both appear, attributed to the right people. Note that an
admin's dashboard reads only go through relaygate once dashboard principals are
supported (see "Known gaps").

### 6. What to look for

- Every `[PASS]`; any `[FAIL]` prints the audit rows involved.
- Scenario 4's first line: with the model classifier on, the ask itself is
  usually refused (`relaygate_classified`, often `model:refused`); without it,
  the inside agent's answers are each refused by the mode bits.
- Scenario 4's sweep line: `canary CANARY-<run>… absent from …`.
- `realtime: control delivery seen on the outside socket` near the top. The
  driver DMs one outside agent from the other over the live node socket; only
  then does the canary sweep cover realtime frames. Without it, scenario 4
  fails (set `ACCEPTANCE_REALTIME=optional` only where realtime isn't proxied).
- Audit rows for the inside agents' attempts are all `deny`, with reasons like
  `mode:660+acl:22:r:prefix` (the bits refused it), `registration
  (prefix_not_own_group)` or `unknown_stream`.
- Each audit row's `policy_version` matches `/readyz`; in scenario 12 two
  versions appear.

### 7. Clean up

Test agents, channels (`acc-<run>`, `pit-acc-doc-<run>`) and sessions
(`acc-local-<run>`, `acc-doc-<run>`) are named by run id. Delete the inside
Deployments when done; the synthetic channels and sessions can stay or be
removed upstream.

## Known gaps

- **Principals without an rg_ token.** The desktop app (uploading with its
  device token) and admins in the dashboard don't hold rg_ tokens yet, so their
  traffic can't go through relaygate until relaygate maps them from relay-control
  by policy. Until then the driver plays the uploader with an rg_ agent.
- **Dropped realtime deliveries** are not acked by relaygate, so they can be
  redelivered (and dropped again) after a reconnect.
- **Filtered lists** (search, session lists) can return short pages.
