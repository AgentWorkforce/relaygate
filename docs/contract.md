# relaygate contract

Status: draft, v0. This is the contract that clients (agents, bridges, MCP
servers), relay-control and relaygate build against. Anything marked **open** is
undecided.

## What relaygate is

A gateway in front of Relaycast and the Sessions API. Agents hold relaygate
tokens only. relaygate holds the Relaycast and Sessions credentials, checks
every request against the caller's group and the resource's mode, and only then
forwards it.

Relaycast and Sessions stay unaware of groups. They get no new fields and no
policy code.

Not in scope: roles (RBAC), separate workspaces per trust level, human
end-user auth to the dashboard.

## Who decides, who enforces

The **operator** defines the policy in **relay-control**, the control plane
they already use. relaygate holds no policy of its own; it enforces what
relay-control defines.

The operator, in relay-control, owns:

- the **groups**: each `gid` and its name;
- the **enrollment keys**: which group each key enrolls into, its optional name
  prefix, creating and revoking keys;
- the **prefix defaults** for streams (`gid`, `mode`, `classify` per prefix);
- **overrides** for a specific stream or session (`gid`, `mode`, `classify`);
- the **classifier settings**.

relaygate pulls this policy from relay-control and keeps it cached, so a
relay-control outage doesn't stop enforcement. A policy change takes effect in
relaygate within a bounded delay. **Open:** the relay-control API for this, and
the delay.

Agents and components can only do what the policy already allows: register
with a key the operator issued, and register a stream inside a prefix their
group owns.

## Principals and groups

- A **principal** is an agent, or a component such as a bridge acting for the
  humans behind it.
- A **group** is a number (`gid`). Every principal is in exactly one group.
- A principal's group is set when it registers and does not change. Moving an
  agent to another group means registering a new agent.

Example deployment with two groups:

| gid | Name | Who |
|---|---|---|
| 11 | local | Agents on people's machines |
| 22 | pit | Agents that may see regulated data (PII under a BAA), running headless on servers, and the bridges that serve humans |

Group numbers and names are per deployment. relaygate has no built-in groups.

## Resources

relaygate guards two kinds of resource:

| Kind | Examples | Read means | Write means |
|---|---|---|---|
| `stream` | a Relaycast channel, an agent's DM inbox, a thread in an outside chat tool, a knowledge base | list and fetch its messages | post into it |
| `session` | a session transcript and its events | list, search and fetch it | upload or append to it |

relaygate knows a stream only by an opaque `id`. It never parses the id or
knows what system is behind it:

- streams relaygate proxies (Relaycast channels and inboxes) get ids that
  relaygate derives from the Relaycast request, such as
  `relaycast:channel/<name>` and `relaycast:inbox/<agent>`;
- streams outside relaygate are named by the component that owns them, for
  example `slack:T123/C456/1731600000.123` or
  `kb:brain-write/slack/general-c1/2026-11-14`.

Every resource has:

- `owner`: the principal that created or registered it;
- `gid`: the owning group, which defaults to the owner's group;
- `mode`: three octal digits for owner, group and other, in that order;
- `classify` (streams only): whether every write is sent to the classifier,
  not only writes that cross a group boundary. Default `false`.

Each digit is a sum of `4` (read) and `2` (write). `1` is reserved. So `6` is
read and write, `4` is read only, `2` is write only and `0` is nothing.

A DM is a write to the recipient's **inbox**, a stream owned by the recipient.
Whether A may DM B is therefore decided by B's inbox mode, and whether B may
answer is decided by A's inbox mode.

### Registering streams and prefix defaults

The owning component registers a stream with its `gid`, `mode` and `classify`.
It may only register an id under a prefix whose default `gid` is its own group,
and an operator override in relay-control wins over what the component set:

```
PUT /v1/streams/{id}
Authorization: Bearer rg_...
{"gid": 22, "mode": "660", "classify": true}
```

A stream id that isn't registered takes the deployment's default for the
longest matching prefix, for example `slack:` → gid 22, mode `660`, classify
on. An id that matches no registered stream and no prefix is refused
(`403 relaygate_denied`).

### Sessions keep their first owner

A session's `owner` and `gid` are set when it is first uploaded. Later uploads
or appends never change them, whoever sends them.

## The check

For a principal `p` doing `op` (`r` or `w`) on resource `x`:

1. If `p` is `x.owner`, use the owner digit.
2. Else if `p.gid == x.gid`, use the group digit.
3. Else use the other digit.

The request is allowed only if that digit contains the bit for `op`. The check
uses nothing but `p.gid`, `x.owner`, `x.gid` and `x.mode`, so the same request
always gets the same answer.

A refused request is answered by relaygate with `403` and
`{"error":"relaygate_denied","op":"w","resource":"<id>"}`. It is never
forwarded upstream.

### Errors clients can rely on

- Every `403` from relaygate is final while the caller's registration and the
  resource's `gid`, `mode` and `classify` stay the same. Clients must not
  retry it unless one of those changes.
- `503 relaygate_unavailable` means relaygate could not decide (for example
  the classifier timed out). Nothing was forwarded. Clients may retry with
  backoff.
- Other `4xx` and `5xx` responses come from Relaycast or Sessions and keep
  their usual meaning.

## Default modes for the pit deployment

These defaults implement the rules "a local agent can message a pit agent, a
pit agent can't answer an agent outside the pit, pit agents can read
everything, local agents only read sessions outside the pit, and only the pit
writes to outside chat tools":

| Resource | gid | Mode | Classify | Pit (22) can | Local (11) can |
|---|---|---|---|---|---|
| Local streams (channels, local inboxes) | 11 | `664` | no | read | read, write |
| Pit streams (channels, pit inboxes) | 22 | `662` | no | read, write | write in, not read back |
| Outside chat tool (prefix `slack:`) | 22 | `660` | yes | read, write | nothing |
| Knowledge base (prefix `kb:`) | 22 | `660` | yes | read, write | nothing |
| Local sessions | 11 | `664` | — | read | read, write |
| Pit sessions | 22 | `660` | — | read, write | nothing |

The `slack:` and `kb:` rows are prefix defaults this deployment configures.
relaygate itself has no notion of Slack or knowledge bases.

Two deliberate choices in this table:

- **Pit agents only read local sessions.** With write access a pit agent could
  copy regulated data into a session that local agents can read, bypassing
  every chat rule.
- **Local agents can't upload into pit sessions.** **Open:** the original matrix
  gives local agents write-only access (`662`). That is only needed if local
  agents hand work to the pit as sessions rather than as messages.

A resource's mode can only be changed by its owner or by the operator in
relay-control, and the change is audited.

## Registration

An agent registers once, through relaygate, with an **enrollment key**. Each
enrollment key belongs to one group, so the key decides the group and the
agent can't pick its own.

```
POST /v1/register
Authorization: Bearer <enrollment key>
{"name": "bridge-c0123-1731600000.123"}

200
{"agent_id": "...", "gid": 22, "token": "rg_..."}
```

After that the agent is in its group and every call it makes is checked.
Nothing else is configured per agent.

- Enrollment keys are created by the operator in relay-control, one or more
  per group, and can be revoked. Revoking a key stops new registrations, not existing agents.
- An enrollment key can be limited to a name prefix (for example `bridge-`).
  Registering a name outside the prefix answers `403 relaygate_name_scope`, so
  a leaked key can't create arbitrary agents in its group.

### Registering a name that already exists

Hosts that create agents on demand (one per chat thread, say) restart and
need the same identity back. At first registration the client may send a
`recovery` value: a proof derived from a secret it keeps.

```
POST /v1/register
Authorization: Bearer <enrollment key>
{"name": "bridge-c0123-1731600000.123", "recovery": "<proof>"}
```

A second registration with the same name:

- with the same enrollment key's group and a matching `recovery` proof returns
  the same `agent_id` and a new token, and revokes the old token;
- otherwise answers `409 relaygate_name_taken`.

The group never changes on re-registration.

### Humans behind a bridge

Humans don't call relaygate. A bridge acts as its own principal in its group
and records the human's id from the outside tool as attribution in message
metadata. If per-human permissions are needed
later, the bridge registers a principal per human with the same enrollment
key.

## Tokens and the upstream credentials

- An `rg_` token only works against relaygate. Relaycast and Sessions don't
  accept it.
- relaygate calls Relaycast and Sessions with its own credentials, and passes
  the acting agent's identity so upstream records the real author.
- Agents never receive a Relaycast or Sessions credential. An agent that has
  one can go around the gate, so a deployment must not hand them out.
- Relaycast and Sessions accept traffic only from relaygate. On Kubernetes this
  is a NetworkPolicy; elsewhere a firewall rule. The gate is only as strong as
  this rule.

For clients, the change is a base URL. Bridges and MCP servers set
their Relaycast and Sessions base URLs to relaygate and use the `rg_` token.
The API paths are unchanged.

### Realtime

Relaycast's realtime path (`POST /v1/agent/node-token`, then the
`/v1/node/ws` WebSocket) also goes through relaygate. relaygate mints and holds
the upstream node token, proxies the WebSocket, and drops every pushed event
the caller may not read. Without this, reads would leak through the event
stream even with REST filtered.

When a token is revoked (re-registration, or an admin), relaygate closes every
WebSocket opened with it.

## Reads and lists

A list or search returns only resources the caller may read. relaygate applies
that filter, either by narrowing the upstream query or by filtering the
response, so Relaycast and Sessions need no group support.

**Open:** filtering after the fact breaks pagination and counts. The Sessions
API likely needs a filter parameter that relaygate sets (for example "only
these gids"), which keeps it unaware of what the gids mean.

## Session uploads

A new session is owned by its first uploader and takes that uploader's group
(see "Sessions keep their first owner"). Pit agents
run headless on Linux servers, so their sessions come from a headless uploader
on that server, authenticated with the agent's `rg_` token, not from the
desktop app.

## The classifier

The mode check runs first. The classifier only sees requests the mode bits
allowed, and of those only:

- a write into another group's resource (for example a local agent messaging a
  pit agent);
- any write into a stream with `classify` on, whatever the writer's group (for
  example every post a bridge sends to an outside chat tool).

Request:

```
{"from": {"agent_id": "...", "gid": 11}, "op": "w",
 "resource": {"kind": "stream", "id": "...", "gid": 22},
 "content": "<message text>"}
```

Response: `{"decision": "allow" | "deny", "reason": "..."}`.

- A `deny` is answered with `403` and `{"error":"relaygate_classified"}`, and
  nothing reaches upstream.
- If the classifier errors or times out, the request is not forwarded and the
  answer is `503 relaygate_unavailable`.
- The classifier is pluggable: a model, rules or both. **Open:** the default
  classifier and its latency budget.

## Egress relaygate doesn't proxy

Some components send data out on paths relaygate never sees: a bridge posting
to an outside chat tool with that tool's own API, or an ingest job writing to a
knowledge base. relaygate holds no third-party tokens. Instead these components
ask relaygate first:

```
POST /v1/check
Authorization: Bearer rg_...
{"op": "w",
 "resource": {"kind": "stream", "id": "slack:T123/C456/1731600000.123"},
 "content": "<text>"}

200 {"decision": "allow"}
403 {"error": "relaygate_denied" | "relaygate_classified"}
503 {"error": "relaygate_unavailable"}
```

`/v1/check` runs the same mode check and classifier as a proxied request. The
caller sends only on `allow`; anything else means don't send. On `allow` the
caller must send exactly the `content` it checked, with no added text,
attachments or other payload the check didn't see. External streams are
registered like any other (see "Registering streams and prefix defaults").

`/v1/check` only works if the component calls it, so only trusted components
in a group may hold third-party credentials, and the deployment's network
rules allow egress to those services only from those components.

## Audit

relaygate records every decision: who, what resource, which op, allowed or
denied, and by which stage (mode or classifier). It never records message
content.

## Open questions

- The relay-control API that relaygate pulls policy from, and how fast a change
  reaches relaygate.
- Local agents writing into pit sessions (`662` or `660`).
- The Sessions API filter parameter for lists and search.
- The default classifier and its latency budget.
- Whether a principal ever needs more than one group.
- What, if anything, the `1` bit means.
