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
  prefix, whether it is a guest key and when it expires, creating and revoking
  keys;
- the **prefix defaults** for streams (`gid`, `mode`, `acl`, `classify` per
  prefix);
- **overrides** for a specific stream or session (`gid`, `mode`, `acl`,
  `classify`);
- the **ceilings**: per group, the groups it may never touch;
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
- A **group** is a number (`gid`). Every principal has one **primary group**,
  set when it registers, and may have **supplementary groups** (like Unix
  supplementary groups). Both come from the enrollment key it registered with,
  so the operator controls them.
- Supplementary groups express tiers of trust. A trusted developer can be in
  `dev` and `dev-trusted`; a work-trial developer only in `dev-trial`.
- The primary group never changes. Supplementary groups follow the current
  policy for the agent's enrollment key, so the operator can widen or narrow
  them without re-registering agents.

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
{"gid": 22, "mode": "660", "acl": [{"gid": 11, "perm": "w"}], "classify": true}
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
2. Else, if any of `p`'s groups (primary or supplementary) is `x.gid`, use the
   group digit.
3. Else use the other digit.
4. If `p` is not `x.owner`, add the bits of every `x.acl` entry naming one of
   `p`'s groups. An ACL entry never removes what steps 1-3 gave.
5. Finally, if a group ceiling forbids one of `p`'s groups from `x.gid` (see
   "Guests"), refuse whatever the steps above allowed.

The request is allowed only if the result contains the bit for `op`. The check
uses nothing but `p`'s groups, `x.owner`, `x.gid`, `x.mode`, `x.acl` and the
policy's ceilings, so the same request always gets the same answer.

### Access lists

Three digits can't say "the pit may read this, a guest may not": both are
"other". So, like POSIX ACLs, a resource may carry extra group entries:

```
"acl": [{"gid": 22, "perm": "r"}, {"gid": 11, "perm": "w"}]
```

`perm` is `r`, `w` or `rw`. Entries only ever add access for the groups they
name; "other" stays the access for everyone else. Prefix defaults, overrides
and registered streams can all carry an `acl`.

A refused request is answered by relaygate with `403` and
`{"error":"relaygate_denied","op":"w","resource":"<id>"}`. It is never
forwarded upstream.

### Errors clients can rely on

- Every `403` from relaygate is final while the caller's registration, the
  resource's `gid`, `mode`, `acl` and `classify`, and the policy's ceilings
  stay the same. Clients must not retry it unless one of those changes (for
  example, a customer adds an ACL entry that shares a session).
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

| Resource | gid | Mode | ACL | Classify | Pit (22) can | Local (11) can |
|---|---|---|---|---|---|---|
| Local streams (channels, local inboxes) | 11 | `660` | 22:r | no | read | read, write |
| Pit streams (channels, pit inboxes) | 22 | `660` | 11:w | no | read, write | write in, not read back |
| Outside chat tool (prefix `slack:`) | 22 | `660` | — | yes | read, write | nothing |
| Knowledge base (prefix `kb:`) | 22 | `660` | — | yes | read, write | nothing |
| Local sessions | 11 | `660` | 22:r | — | read | read, write |
| Pit sessions | 22 | `660` | — | — | read, write | nothing |

Every default leaves "other" at `0`, so a group the operator adds later (a
guest, say) starts with no access to anything and is granted only what an ACL
names.

Stream ids for inboxes carry the agent's name, so the prefix defaults only
place an inbox in the right group if names do. In this deployment each
enrollment key has its own name prefix (`local-`, `pit-`, `slack-`, `guest-`)
and inbox defaults are per prefix, with no catch-all: an inbox that matches no
prefix is refused rather than defaulting into the wrong group.

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

## Guests

A guest is someone from outside the organization, a contractor or a vendor,
working in the workspace with their own agents: for example a vendor's
engineer whose agents collaborate with the customer's on a design, and who
reads the sessions the customer chooses to share. Guests are an ordinary group
with three extra rules:

- **Guest keys.** An enrollment key marked `"guest": true` enrolls guests.
  It should carry `expiresAt`; after it, the key enrolls no one and every token
  issued from it stops working. Revoking a guest key (in relay-control) ends
  all its agents' tokens at once, not only new registrations.
- **Ceilings.** The operator can set, per group, the groups it may never touch:
  `"ceilings": [{"gid": 44, "never": [22]}]`. No mode, ACL or stream
  registration can grant a guest access to the pit. It is the last step of the
  check, so a mistaken ACL can't open it.
- **Provenance.** Everything a guest's agent sends carries
  `"relaygate": {"agent": "...", "groups": ["guest"], "guest": true}`, so the
  customer's agents always know they are talking to someone outside.

What a guest gets is only what ACLs name. A typical collaboration grant:

| Resource | gid | Mode | ACL | Guest (44) can |
|---|---|---|---|---|
| A shared channel, e.g. prefix `relaycast:channel/collab-` | 11 | `660` | 44:rw | read, write |
| Local agents' inboxes that opt in | 11 | `660` | 44:w | message them, not read their inbox |
| The guest's own inboxes | 44 | `660` | 11:w | read, write; local agents can answer |
| Sessions the customer shares | 11 | `660` | 44:r (per session) | read those sessions only |
| Anything in the pit | 22 | — | — | nothing, by ceiling |

Every guest write that crosses a group boundary, or goes to a stream with
`classify` on, is classified (a guest posting in a shared local channel always
is). Every guest decision is audited like any other.

What relaygate doesn't cover: a guest's *human* seat in the dashboard
(signing in, which pages and sessions they see) is relay-control's job, with
the same groups.

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
  per group, and can be revoked. A key may carry `expiresAt`; after it the
  key enrolls no one. Revoking or expiring an ordinary key stops new
  registrations and leaves existing agents working; revoking or expiring a
  guest key (see "Guests") also ends every token issued from it.
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
  the acting agent's identity so upstream records the real author. Relaycast
  has no act-as for agents, so relaygate registers each agent upstream under
  the same name (with the workspace key, `auto_join_general: false`) and keeps
  that agent's `at_live_` token sealed (AES-GCM, key from `RELAYGATE_SECRET`)
  in its database. If Relaycast stops accepting the token, relaygate takes the
  identity over with the workspace key and retries once.
- Agents never receive a Relaycast or Sessions credential. An agent that has
  one can go around the gate, so a deployment must not hand them out.
- Relaycast and Sessions accept traffic only from relaygate. On Kubernetes this
  is a NetworkPolicy; elsewhere a firewall rule. The gate is only as strong as
  this rule.

For clients, the change is a base URL. Bridges and MCP servers set
their Relaycast and Sessions base URLs to relaygate and use the `rg_` token.
The API paths are unchanged.

### Proxied Relaycast routes

relaygate forwards an allowlist; every other `/v1` route answers `404
relaygate_route_not_proxied` without reaching Relaycast. Several Relaycast reads
skip membership checks, so relaygate checks each one itself:

| Route | Check |
|---|---|
| `GET /v1/agent`, `POST /v1/agents/heartbeat`, `/disconnect` | self |
| `GET /v1/agents`, `GET /v1/agents/:name` | answered with the workspace key, filtered to agents whose inbox the caller may write or read |
| `GET /v1/channels` | filtered to channels the caller may read |
| `POST /v1/channels` | `w` on `relaycast:channel/<name>` |
| `GET /v1/channels/:name`, `/messages`; `POST .../join` | `r` on the channel |
| `POST /v1/channels/:name/leave`, `/mute`, `/unmute` | self |
| `POST /v1/channels/:name/messages` | `w` on the channel (classifier as usual) |
| `GET /v1/messages/:id`, `/replies`, `/reactions`; `POST .../read`; `DELETE .../reactions/:emoji` | `r` on the message's channel; a DM message only for its two participants |
| `POST /v1/messages/:id/replies`, `/reactions` | `w` on the message's channel; refused under a DM (answer with `POST /v1/dm`) |
| `POST /v1/dm` | `w` on `relaycast:inbox/<to>` |
| `GET /v1/dm/conversations`, `GET /v1/dm/:cid/messages` | the caller's own 1:1 conversations (group DMs aren't proxied) |
| `GET /v1/search`, `GET /v1/inbox` | filtered: channel hits the caller may read, DM hits it wrote |

Channel names starting `dm-` (Relaycast's hidden DM channels) are never
addressable as channels. On every write relaygate drops `from` (which lets a
node post as another agent upstream), replaces `data.relaygate` with the
verified sender card, and passes `data` and the `Idempotency-Key` header
through unchanged. Message ids are Relaycast's.

Errors on proxied routes use Relaycast's shape, so SDK clients surface them:
`{"ok": false, "error": {"code": "relaygate_denied", "message": "..."}, "op":
"w", "resource": "<id>"}`. The codes are the ones in "Errors clients can rely
on".

### Realtime

Relaycast's realtime path (`POST /v1/agent/node-token`, then the
`/v1/node/ws` WebSocket) also goes through relaygate. `node-token` answers an
`rgn_` token; relaygate mints and keeps the upstream `nt_live_` token, opens
the upstream socket itself, and:

- forwards only `node.register` (forced to the agent's own node id, with no
  capabilities), `node.heartbeat` and `delivery.ack` for the agent itself;
  any other client frame is refused with an `error` frame;
- forwards a `deliver` only if it is for the agent and the agent may read its
  stream (`message.created` and `thread.reply` by `channel_name`, `dm.received`
  by the agent's inbox); action invocations, context updates and group DMs
  are dropped. Without this, reads would leak through the event stream even
  with REST filtered.

A node token works only while the `rg_` token that minted it does. When that
token is revoked (re-registration, a guest key ending), relaygate closes every
socket opened with it (close code `4401`), at once and at the latest on its
next revalidation. Relaycast's `/v1/ws` refuses agent tokens and isn't
proxied.

**Open:** a dropped delivery is never acked to Relaycast by relaygate (an ack is
cumulative and would acknowledge frames the client hasn't processed), so it may
be redelivered on reconnect, and dropped again.

### The sender's groups travel with the message

Every message relaygate forwards carries the sender's verified groups, so the
recipient knows who is asking and with what scope:

```
"data": {"relaygate": {"agent": "<name>", "groups": ["dev", "dev-trusted"]}}
```

relaygate removes any `relaygate` field the client sent, so it can't be forged.
`GET /v1/whoami` returns the same card for the caller.

## Reads and lists

A list or search returns only resources the caller may read. relaygate applies
that filter, either by narrowing the upstream query or by filtering the
response, so Relaycast and Sessions need no group support.

**Open:** filtering after the fact breaks pagination and counts. The Sessions
API likely needs a filter parameter that relaygate sets (for example "only
these gids"), which keeps it unaware of what the gids mean.

## Session uploads

A new session is owned by its first uploader and takes that uploader's group
(see "Sessions keep their first owner"). Its mode and ACL come from the
policy's `sessionDefaults` for that group (a group without one gets `600`),
then any `sessionOverrides` entry for that session id, which is how a customer
shares one session with a guest:

```
"sessionDefaults": [{"gid": 11, "mode": "660", "acl": [{"gid": 22, "perm": "r"}]},
                    {"gid": 22, "mode": "660"}],
"sessionOverrides": [{"id": "<session id>", "acl": [{"gid": 44, "perm": "r"}]}]
```

The Sessions proxy is mounted at `/sessions`: a client's Sessions base URL
becomes `https://<relaygate>/sessions` and the paths stay the same. relaygate
calls Sessions with one service token (`rth_st_`, `rth:sync` and `rth:read`).

| Route | Check |
|---|---|
| `POST /sessions/v1/sessions/:id/turns` | `w` on the session; `sessionOwner` on the body and every turn is set to the agent |
| `POST /sessions/v1/ingest` | `w` on every session the batch names; all or nothing |
| `GET /sessions/v1/sessions` | filtered to sessions the caller may read; the cursor passes through |
| `GET /sessions/v1/sessions/:id/{events,turns,metadata,thread,catalog,timing,analysis,brief}` | `r` on the session |
| `GET /sessions/v1/events?session=<id>` | exactly one `session`, `r` on it |

A write is decided before anything is recorded, and a new session is claimed
only when the whole request is allowed, so a refused upload never makes its
sender an owner. Sessions that never came through relaygate have no owner and
are invisible through it. Other Sessions routes (including the desktop
uploader's `/v1/delivery/*`) answer `404 relaygate_route_not_proxied`. Pit agents
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

## Explain

An operator (or an agent drafting a policy for one) can ask "may X do op on
Y, and why" without sending anything. Explain runs the same deterministic check
as a real request, against the live policy or a draft, and never calls the
classifier; it says whether the classifier would run.

```
POST /admin/v1/explain
Authorization: Bearer <admin token>
{"as": {"key": "vendor-guest"}, "op": "w",
 "resource": {"kind": "stream", "id": "relaycast:inbox/pit-a"},
 "policy": { ...optional draft... }}

200
{"draft": false, "decision": "deny", "reason": "ceiling:44->22:prefix",
 "classified": false, "summary": "guest-<new> may not write ...: refused by a ceiling",
 "steps": [{"step": "subject", "detail": "..."}, {"step": "resource", ...},
           {"step": "other", ...}, {"step": "ceiling", ...}]}
```

`as` is a registered agent (`{"agent": "<name>"}`), a new agent enrolled with
a key (`{"key": "<id>", "name"?}`), or bare groups (`{"gid": 44, "groups":
[]}`). A body with `cases` instead runs a list of expected decisions
(`"expect": "allow" | "deny"`, optionally `"classified"`) and reports which
fail, so a drafted policy can carry its own tests. An invalid draft answers
`400 relaygate_bad_policy` with the reason. Nothing is applied and nothing is
audited as a decision.

The same check runs offline: `relaygate-explain --policy <file> --as
key:vendor-guest --op w --stream <id>`, or `--cases <file>`, which exits `1`
when any case fails (see `examples/cases.pit.json`).

**Open:** in production the admin endpoint belongs behind relay-control, which
holds the policy; today it is enabled by `RELAYGATE_ADMIN_TOKEN`.

## Audit

relaygate records every decision: who, what resource, which op, allowed or
denied, and by which stage (mode or classifier). It never records message
content.

## Open questions

- How a customer shares one session with a guest from the dashboard (a
  per-session ACL entry set through relay-control).
- Whether a guest's own uploaded sessions should be readable by the customer
  by default (`44`-owned sessions with ACL `11:r`).
- The relay-control API that relaygate pulls policy from, and how fast a change
  reaches relaygate.
- Local agents writing into pit sessions (`662` or `660`).
- The Sessions API filter parameter for lists and search.
- The default classifier and its latency budget.
- Whether tool calls (Relaycast actions) need to be their own guarded
  resource, beyond streams and sessions.
- What, if anything, the `1` bit means.
