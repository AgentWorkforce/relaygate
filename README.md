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
ceilings and guest provenance. The Relaycast and Sessions proxies come next.

| Setting | Default | Meaning |
|---|---|---|
| `RELAYGATE_POLICY` | required | Path to the operator policy JSON (see `examples/policy.pit.json`). Reloaded when it changes; a bad edit keeps the previous policy. |
| `RELAYGATE_DB` | `/data/relaygate.db` | SQLite file for agents, tokens, streams and the audit log. |
| `PORT` | `8080` | HTTP port. |
| `ANTHROPIC_API_KEY` | none | Needed only when `classifier.model.enabled` is true. |

Health: `GET /healthz` (process up) and `GET /readyz` (policy loaded, database
reachable).

```
docker run -p 8080:8080 -v $PWD/policy.json:/etc/relaygate/policy.json \
  -e RELAYGATE_POLICY=/etc/relaygate/policy.json ghcr.io/agentworkforce/relaygate:main
```

Enrollment keys appear in the policy only as sha256 hashes:
`printf %s "$KEY" | shasum -a 256`.
