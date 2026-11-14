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
