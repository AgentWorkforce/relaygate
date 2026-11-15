# relaygate

Group permissions and egress control for agents.

relaygate sits in front of Relaycast (chat) and Sessions (transcripts). Every
agent talks to those services through it. Relaycast and Sessions stay simple
and know nothing about permissions; relaygate decides who may read and write
what.

- **Groups, not roles.** An agent joins one group when it registers.
- **Mode bits, like a filesystem.** Each resource has an owner and a mode such
  as `662`: read and write bits for the owner, the owner's group, and everyone
  else.
- **Deterministic first.** A request the mode bits refuse never reaches
  Relaycast or Sessions.
- **Then a classifier.** Messages that cross a group boundary are checked for
  attempts to pull out information they shouldn't.

The contract is in [docs/contract.md](docs/contract.md).

## Running it

Build 1 implements registration, `rg_` tokens, the mode check, stream
registration, `POST /v1/check`, the classifier (rules, then optionally Claude)
and the audit log. It also implements access lists (`acl`), guest enrollment
keys (`guest`, `expiresAt`; revoking or expiring one ends its tokens), group
ceilings and guest provenance. Build 2 adds the Relaycast proxy: point a
Relaycast client's base URL at relaygate and use the `rg_` token (see
"Proxied Relaycast routes" in the contract). The Sessions proxy is mounted at `/sessions`.

| Setting | Default | Meaning |
|---|---|---|
| `RELAYGATE_POLICY` | required | Path to the operator policy JSON (see `examples/policy.pit.json`). Reloaded when it changes; a bad edit keeps the previous policy. |
| `RELAYGATE_DB` | `/data/relaygate.db` | SQLite file for agents, tokens, streams and the audit log. |
| `PORT` | `8080` | HTTP port. |
| `RELAYGATE_ADMIN_TOKEN` | none | Enables `POST /admin/v1/explain` (operator "may X do op on Y, and why"). |
| `RELAYCAST_URL` | none | Turns on the Relaycast proxy (REST allowlist and `/v1/node/ws`). |
| `RELAYCAST_WORKSPACE_KEY` | none | `rk_live_` key relaygate uses to register agents upstream. Required with `RELAYCAST_URL`. |
| `RELAYGATE_SECRET` | none | At least 32 characters; seals the upstream agent and node tokens at rest. Required with `RELAYCAST_URL`. |
| `SESSIONS_URL` | none | Turns on the Sessions proxy at `/sessions` (uploads and reads to one origin). |
| `SESSIONS_UPLOAD_URL`, `SESSIONS_READ_URL` | `SESSIONS_URL` | Separate upload and read origins. |
| `SESSIONS_HOSTS` | none | Comma-separated hosts whose requests are Sessions requests at the root path (a history origin pointed at relaygate). |
| `SESSIONS_TOKEN` | none | Optional fallback Sessions credential for callers that send none; callers normally forward their own in `Authorization`, with their rg_ token in `X-Relaygate-Token`. |
| `ANTHROPIC_API_KEY` | none | Needed only when `classifier.model.enabled` is true. |

Health: `GET /healthz` (process up) and `GET /readyz` (policy loaded, database
reachable).

```
docker run -p 8080:8080 -v $PWD/policy.json:/etc/relaygate/policy.json \
  -e RELAYGATE_POLICY=/etc/relaygate/policy.json ghcr.io/agentworkforce/relaygate:main
```

Enrollment keys appear in the policy only as sha256 hashes:
`printf %s "$KEY" | shasum -a 256`.

## Testing a policy

`relaygate-explain` (`npm run explain --` in a checkout) answers "may X do op on
Y, and why" from a policy file, without a running gate:

```
npm run explain -- --policy policy.json --as key:vendor-guest --op r --stream relaycast:inbox/pit-a
DENY  guest-<new> may not read relaycast:inbox/pit-a: refused by a ceiling
  ...
npm run explain -- --policy draft.json --cases examples/cases.pit.json   # exits 1 on any failure
```

`--as` is `agent:<name>` (with `--db`), `key:<id>[:<name>]` or
`gid:<gid>[,<gid>...]`. Use `--session <id> [--session-gid <gid>]` instead of `--stream` for
sessions.

Example policies with their cases: `examples/policy.pit.json` (with a guest)
and `examples/policy.double-pit.json` (two groups: laptops outside the
regulated boundary, cloud agents inside it).

