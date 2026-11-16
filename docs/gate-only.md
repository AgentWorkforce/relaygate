# Gate-only deployments

In a gate-only deployment, relaygate is the only way into Relaycast and Sessions
for anyone outside the cluster: the public Relaycast origin (`cast.*`) and the
public Sessions origin (`history.*`) route to relaygate, and Relaycast,
session-ingest and session-read-api admit only relaygate and a short list of
in-cluster components. Without that network rule, relaygate's decisions are
advisory: any member holding a Relaycast or Sessions credential can go around
it (acceptance scenario 14 checks Sessions).

## What goes through relaygate

| Caller | Credential | Through relaygate as |
|---|---|---|
| Agents that enrol with an enrollment key | `rg_` | relaygate principals in the key's group (Relaycast and Sessions) |
| The desktop app uploading sessions | its device token (`sh_at_`) | a Control principal mapped by `controlPrincipals` |
| The dashboard reading sessions | Control-issued read tokens (`rth_at_read_`, `rth_st_read_`) | a Control principal, learnt when relay-control mints the token through relaygate |
| relay-control minting read tokens | the read API's internal secret | forwarded to the read API (internal path only, never on a public host) |

See the contract: "Proxied Relaycast routes", "Session uploads", "Control
principals".

## What stays direct (in-cluster only)

relay-control, Chief and relayflows workers call Relaycast and Sessions
in-cluster with their own server-side credentials. The NetworkPolicy admits
them explicitly; they are never reachable through the public origins. relaygate
needs egress to Relaycast, session-ingest, session-read-api and relay-control
(introspection).

## What breaks until it moves behind relaygate

- **Desktop app Relaycast features from laptops.** The desktop's local broker
  talks to Relaycast with the shared workspace key and per-agent `at_live_`
  tokens, which relaygate can't authorize by group, and it uses routes relaygate
  doesn't proxy (agent registration with the workspace key, the delivery queue,
  spawn nodes and actions, files). With the public Relaycast origin routed to
  relaygate, those stop working from laptops until desktop agents enrol through
  relaygate (`/v1/register`) and the delivery queue is proxied. Desktop session
  uploads keep working (device tokens).
- **Anything else outside the cluster that holds a Relaycast workspace key or
  agent token**: CLI use against the public origin, external integrations.
- Relaycast routes relaygate doesn't proxy (see the contract's route table) and
  the Sessions routes it deliberately refuses (`/v1/turns/batches`,
  `/v1/cli/login`).

The trade is deliberate: a regulated boundary only holds if every outside
caller is a relaygate principal.

## Switching on

1. relaygate: `RELAYCAST_URL`/`RELAYCAST_WORKSPACE_KEY`/`RELAYGATE_SECRET`;
   `SESSIONS_UPLOAD_URL`/`SESSIONS_READ_URL`; `SESSIONS_HOSTS` (the history
   host); `RELAYCONTROL_INTROSPECT_URL`/`RELAYCONTROL_INTROSPECT_SECRET`/
   `SESSION_INGEST_AUDIENCE`; `SESSIONS_INTERNAL_SECRET`;
   `SESSIONS_CORS_ORIGINS`; `RELAYGATE_ADMIN_TOKEN`.
2. Policy: `controlPrincipals` (who is in which group; until relay-control's
   mint carries role and email, dashboard users match by `userIds`),
   `sessionAggregates` (who sees cross-session views), and `sessionDefaults`
   with read ACLs for any admin group. Test it with `relaygate-explain`.
3. relay-control: its session read API URL (`SESSION_READ_API_URL`) is a bare
   origin, so give relaygate an internal Sessions listener (`SESSIONS_PORT`,
   e.g. 8081, served at its root, on a ClusterIP Service only) and point
   relay-control at that origin, e.g.
   `http://agent-relay-relaygate-sessions.<ns>.svc.cluster.local:8081`. Never
   route that port publicly: it accepts relay-control's internal mint calls.
   relaygate's introspection audience must be one Control accepts.
4. Network: public `cast.*` and `history.*` route to relaygate; NetworkPolicy
   on Relaycast, session-ingest and session-read-api admits only relaygate and
   the in-cluster components above.
5. Adopt sessions uploaded before the switch, or they become invisible:
   `POST /admin/v1/sessions/adopt?dryRun=1`, check the report, then run it
   without `dryRun` (contract: "Adopting existing sessions").
6. Run the acceptance test (`docs/acceptance-pit.md`), including scenario 14
   with `DIRECT_SESSIONS_READ_URL` set to the public history origin: it must now
   pass.
