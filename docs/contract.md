# relaygate contract

Status: draft, v0. This is the contract that clients (agents, bridges, MCP
servers), relay-control and relaygate build against. Anything marked **open** is
undecided.

## What relaygate is

A gateway in front of Relaycast and the Sessions API. relaygate checks every
request against the caller's group and the resource's mode, and only then
forwards it. For Relaycast, agents hold relaygate tokens only and relaygate
holds the Relaycast credentials. For Sessions, callers keep their own Sessions
credential, which relaygate forwards unchanged after checking the caller (see
"Session uploads" and "Control principals").

Relaycast and Sessions stay unaware of groups. They get no new fields and no
policy code.

Not in scope: roles (RBAC), separate workspaces per trust level, human
end-user auth to the dashboard.

## Who decides, who enforces

The **operator** defines the policy; relaygate only enforces it. It lives in
**relay-control**, the control plane they already use (pulled, below), or in a
JSON file (`RELAYGATE_POLICY`, on Kubernetes a ConfigMap): relaygate checks the file for changes every few seconds
(`RELAYGATE_POLICY_RELOAD_MS`, default 5000), applies a new version once it
parses, and keeps the last good policy if an edit doesn't. Each audit row
records the version in force (see "Audit").

The operator owns:

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

**From relay-control:** with `RELAYCONTROL_POLICY_URL` set (instead of
`RELAYGATE_POLICY`), relaygate pulls the policy from relay-control
(docs/design/control-owned-policy.md):

```
GET <RELAYCONTROL_POLICY_URL>
Authorization: Bearer <RELAYCONTROL_POLICY_SECRET>
If-None-Match: "<version in force>"

200  ETag: "<version>"
     X-Relaycontrol-Signature: v1=<hex HMAC-SHA256(secret, the exact body bytes)>
     {"version": <positive integer>, "updatedAt": "...", "policy": {...the file's shape...}}
304  (no body, no signature): unchanged
```

relaygate applies an answer only if its signature verifies over the bytes it
received, the policy parses, and the version is newer than the one in force
(a rollback is published as a new, higher version). Anything else keeps the
policy in force and is reported by `GET /admin/v1/policy/status` (`source`,
`version`, `hash`, `appliedAt`, `lastFetchAt`, `lastError`, `lastRejected`).
Each applied answer is cached in the database exactly as served and
re-verified on startup, so a restart while relay-control is down keeps
enforcing it. With nothing applied or cached, relaygate fails closed: every
route except `/healthz` and the status route answers `503
relaygate_unavailable`, `/readyz` stays 503, and nothing is forwarded. Audit
rows record pulled versions as `c<version>-<hash>`.

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

An inbox id, `relaycast:inbox/<name>`, resolves like any stream: an operator
override for the exact id, then a registered stream, then the longest matching
prefix default. When none of those places it and an agent with that name is
registered, the inbox follows that agent: it is owned by the agent, takes the
agent's group, and gets the mode, ACL and classify flag of the policy's
`inboxDefaults` entry for that group, or `660` with no ACL when the group has
no entry (so its own group may message it and no one else). A name no agent
has is still refused as an unknown stream, and so is a relay-control user's
`ctl:` identity (it holds no token to read an inbox with). Audit reasons for such an inbox end
in `:agent-inbox`.

```
"inboxDefaults": [{"gid": 11, "mode": "660", "acl": [{"gid": 22, "perm": "r"}]}]
```

`inboxDefaults` names each group at most once. A derived inbox counts for
messaging and reading, not for the agent directory below: it doesn't by itself
show the agent to anyone.

### The agent directory

Who appears in `GET /v1/agents` (and `GET /v1/agents/:name`) is, by default,
the agents a caller could message or whose inbox it may read. To let a group
see agents beyond that, without any right to message them, the operator grants
`r` on their directory entries, `relaycast:agent/<name>`. Only `r` is ever
checked on an entry: it shows the agent's name, status, persona and card, and
nothing else (DMs still need `w` on `relaycast:inbox/<name>`). For example, the
pit sees every agent on the relay while local agents' view is unchanged:

```
"streamDefaults": [{"prefix": "relaycast:agent/", "gid": 22, "mode": "040"}, ...]
```

Entries are operator policy only: an override for the exact id, or a prefix
default that itself starts with `relaycast:agent/`. A broader default (such as
`relaycast:`) and registered stream rows never count, and `PUT
/v1/streams/{id}` refuses every `relaycast:agent/` id, so an agent can't show
itself, or anyone else, to another group. Ceilings apply as usual.

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
and inbox defaults are per prefix. Agents a person's desktop enrols (through
`controlPrincipals`) are named by their harness (`cursor-…`, `claude-…`), so no
prefix covers them; their inboxes follow the registered agent instead (see
"Resources" above): its own group, with `inboxDefaults` for gid 11 mirroring the
`local-` rule. There is still no catch-all: an inbox whose name no prefix
covers and no registered agent has is refused rather than defaulting into the
wrong group, and a gid-22 agent never gets `w` on a gid-11 inbox unless the
policy grants it.

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

### Enrolling with a device token

An agent run by a person's desktop app enrols with that person's relay-control
device token instead of an enrollment key:

```
POST /v1/register
Authorization: Bearer sh_at_...
{"name": "<name>", "recovery": "<proof>"}

200 {"agent_id": "...", "gid": 11, "token": "rg_...", "expires_at": "<ISO-8601>",
     "user_id": "<control user id>"}
```

- relaygate introspects the device token with relay-control (as for Sessions,
  "Control principals") and maps the person through `controlPrincipals`; the
  agent gets that rule's `gid` and `groups`. A rule may set `namePrefix`, and
  then names outside it answer `403 relaygate_name_scope`. Names starting
  `ctl:` are reserved.
- The token expires (`expires_at`): at the device token's own expiry, and at
  most 24 hours after registration. Before then the app registers again with
  the same `name` and `recovery`, which returns the same `agent_id` and a new
  token and revokes the old one; that is also how a revoked device token, or a
  person removed from the org, stops their agents within a day at most. An expired token answers `401 relaygate_unauthenticated`, the cue to
  register again.
- Re-registration with the same name works only for the same person (the
  same relay-control user) and the same `recovery` proof; otherwise `409
  relaygate_name_taken`.
- Errors: `401 relaygate_unauthenticated` (an inactive device token), `403
  relaygate_denied` (no `controlPrincipals` rule matches the person, or the
  device token lacks the `cli:auth` scope), `403 relaygate_name_scope`, `409
  relaygate_name_taken`, `503 relaygate_unavailable` (relay-control can't
  answer).

How the desktop learns it is gate-only: relay-control's
`GET /api/v1/workspaces/{id}/resolve` returns `urls.relaygateUrl` (a bare https
origin) and omits `relaycastApiKey` when relay-control has
`SELFHOST_RELAYGATE_PUBLIC_URL` set. The presence of `relaygateUrl` means
gate-only: the client enrols at `<relaygateUrl>/v1/register` with its device
token and sends all agent traffic to that origin. Credentials relaygate
doesn't accept, such as a Relaycast `at_live_` agent token or a Relaycast node
token (`nt_live_`) on `/v1/node/ws`, don't work through the gate.

### Launched agents

An agent a person launches on a spawn node enrols with the one-time launch
credential relay-control hands the node for that launch (`sh_lt_…`, scope
`relay:agent:enrol`, introspecting as `principal_type: "relay_launch"` with the
launching person and a fixed `agent_name`):

```
POST /v1/register
Authorization: Bearer sh_lt_...
{"name": "<the credential's agent_name>"}

200 {"agent_id", "gid", "token": "rg_...", "expires_at", "user_id"}
```

- The name must equal the credential's `agent_name` (else `403
  relaygate_name_scope`). The person is mapped through `controlPrincipals`
  (`kinds: ["launch"]` selects launch credentials); the agent gets that
  rule's group.
- relay-control burns the credential on redemption; relaygate never caches its
  introspection. A relaunch is a fresh credential naming the same agent, and
  returns the same `agent_id` (no recovery proof: the single-use credential is
  the proof).
- The token expires after 24 hours, whatever the launch credential's own
  (short) expiry. Because the credential can't be reused, a launched agent
  renews its own token before then:

```
POST /v1/token/refresh
Authorization: Bearer rg_...   (the current, unexpired token)

200 {"token": "rg_...", "expires_at": "<ISO-8601>"}
```

  which revokes the presented token. Only launched agents refresh: a desktop
  agent re-registers with its device token (so a revoked device token stops
  it), and an enrollment-key agent's token doesn't expire (`403
  relaygate_denied` for both). Removing the agent (`DELETE /v1/agent`, or a
  release) ends it.

A spawn invocation carries the launching person's task to a node, so a
control plane checks it before sending: `POST /v1/check` accepts a
relay-control device token as the caller (the launching person), with node
streams named `node:<workspace>/<node>` and placed by prefix defaults like any
stream. The check writes nothing. It never accepts a launch credential:
introspecting one redeems it, and the node could no longer register.

Enrollment key ids `control`, `device:*`, `launch:*` and `hosted:*` are
reserved, and an enrollment key never recovers a desktop-enrolled, launched or
hosted agent.

### Hosted participants

A hosted participant is an agent relay-control runs for a person's MCP
connector (a chat in ChatGPT, a Cursor cloud agent, any MCP client that joins
the relay through relay-control's hosted MCP endpoint, without Agent Relay
Desktop). On a gate-only install relay-control enrols each one here with a
one-time hosted credential (`sh_ht_…`, scope `relay:hosted:enrol`,
introspecting as `principal_type: "relay_hosted"` with the person, a fixed
`agent_name` and the `client` it belongs to):

```
POST /v1/register
Authorization: Bearer sh_ht_...
{"name": "<the credential's agent_name>"}

200 {"agent_id", "gid", "token": "rg_...", "expires_at", "user_id"}
```

- `client` is one of `chatgpt`, `grok-bot`, `muse`, `cursor-cloud` or `mcp` (any
  other MCP client). relay-control derives it from the connector's registered
  OAuth redirect URIs, never from a name the client reports. An unknown or
  missing client makes the credential invalid (`401`).
- **Fails closed.** A hosted credential matches only `controlPrincipals` rules
  whose `kinds` lists `"hosted"`. A rule without `kinds`, such as the usual
  catch-all `{"match": {"orgIds": ["<org>"]}, "gid": 11}`, never matches one.
  With no matching rule, registration answers `403 relaygate_denied`. The
  detail names the rule to add, and the audit reason is
  `no_hosted_rule:<client>`. A hosted participant can't silently land in the
  group meant for people's desktops.
- `match.clients` narrows a rule to some clients. Only hosted credentials
  carry a client, so a rule with `clients` must list `"hosted"` in `kinds`
  (the policy is refused otherwise).
- The name must equal the credential's `agent_name`, and the rule's
  `namePrefix` applies. `reservedNamePrefixes` don't apply: relay-control is
  the control plane those names are reserved for. So an operator can reserve
  `cursor-cloud-` against desktops and enrollment keys and still let hosted
  Cursor agents enrol it.
- Like a launch credential, relay-control burns it on redemption. relaygate
  never caches its introspection and accepts it only at `/v1/register` (never
  on Sessions or `/v1/check`). A rejoin is a fresh credential naming the same
  agent, and returns the same `agent_id`. The token lives 24 hours and renews
  with `POST /v1/token/refresh`.
- The agent's key id is `hosted:<userId>`. `whoami` carries the person's
  `user_id`, and no enrollment key or desktop can recover it.

Example rules, one per client an operator allows (put them before any
catch-all; order only matters among rules that can match):

```
"controlPrincipals": [
  {"match": {"orgIds": ["<org>"], "kinds": ["hosted"], "clients": ["cursor-cloud"], "as": ["agent"]}, "gid": 22, "namePrefix": "cursor-cloud-"},
  {"match": {"orgIds": ["<org>"], "kinds": ["hosted"], "clients": ["chatgpt", "muse"], "as": ["agent"]}, "gid": 22},
  {"match": {"orgIds": ["<org>"], "kinds": ["hosted"], "clients": ["mcp"], "roles": ["owner", "admin"], "as": ["agent"]}, "gid": 22},
  ...
  {"match": {"orgIds": ["<org>"]}, "gid": 11}
],
"reservedNamePrefixes": ["cursor-cloud-"]
```

Hosted participants run outside the company network, in someone else's cloud,
so the pit (gid 22) is the natural home: they may write into local inboxes
only as `inboxDefaults` allow, and never read local.

**Migration.** Before this, relay-control registered hosted participants in
Relaycast directly with the workspace key, so on gate-only installs they
bypassed relaygate. Once relay-control enrols them here, an install whose
policy has no hosted rule refuses them. Each hosted participant's next
`join_relay` (or tool call) fails with the missing rule named, until the
operator adds rules like the ones above.

### Reserved names

`reservedNamePrefixes` in the policy lists agent name prefixes no one may enrol
at `/v1/register` (`403 relaygate_name_scope`), for names a control plane
registers server-side (e.g. `["control-"]`). `ctl:` is always reserved.

### Person identities

`"personNames": {"prefix": "person-", "hashLength": 16}` gives each
relay-control user one person identity, named `<prefix><first hashLength hex
of sha256(userId)>`:

- Only that user enrols it, with their device token, whatever their rule's
  `namePrefix` or `reservedNamePrefixes` say. Every other registration of a
  name with the prefix (another person, a launch credential, an enrollment
  key) answers `403 relaygate_name_scope`.
- It is one identity across their computers. Each computer registers with its
  own recovery proof and gets its own token; registering again from a computer
  rotates only that computer's token (registering without a proof rotates the
  tokens issued without one).
- Other desktop agent names keep the usual rule: one recovery proof, and a
  second computer gets `409 relaygate_name_taken`.

### Agent status and removal

```
PATCH /v1/agent           {"status"?, "persona"?, "metadata"?, "skills"?}
DELETE /v1/agent
Authorization: Bearer rg_...
```

`PATCH` updates the caller's own upstream agent (relaygate forwards it to
Relaycast's `PATCH /v1/agents/<name>` with the workspace key); a
`metadata.relaygate` key is dropped. `DELETE` removes the caller's upstream
agent, revokes all of its `rg_` tokens and closes its sockets; the name stays
reserved for that owner (the same enrollment key or person, with the recovery
proof). An agent can only change itself.

### Humans behind a bridge

Humans don't call relaygate. A bridge acts as its own principal in its group
and records the human's id from the outside tool as attribution in message
metadata. If per-human permissions are needed
later, the bridge registers a principal per human with the same enrollment
key.

## Tokens and the upstream credentials

- An `rg_` token only works against relaygate. Relaycast and Sessions don't
  accept it.
- relaygate calls Relaycast with its own credentials, and passes the acting
  agent's identity so upstream records the real author. Relaycast has no
  act-as for agents, so relaygate registers each agent upstream under
  the same name (with the workspace key, `auto_join_general: false`) and keeps
  that agent's `at_live_` token sealed (AES-GCM, key from `RELAYGATE_SECRET`)
  in its database. If Relaycast stops accepting the token, relaygate takes the
  identity over with the workspace key and retries once.
- Agents never receive a Relaycast credential. An agent that has one can go
  around the gate, so a deployment must not hand them out.
- Sessions is different: callers do hold their own Sessions credentials (device
  tokens, read tokens), and relaygate forwards them unchanged after checking
  the caller. relaygate holds no Sessions credential of its own (an optional
  `SESSIONS_TOKEN` fallback aside), so Sessions keeps recording the real
  person.
- Relaycast and Sessions accept traffic only from relaygate. On Kubernetes this
  is a NetworkPolicy; elsewhere a firewall rule. The gate is only as strong as
  this rule, and for Sessions it is the whole boundary: a member holding a
  Sessions credential can read whatever Sessions serves them wherever Sessions
  is reachable without relaygate, including a public history host not routed
  through it (acceptance scenario 14 checks this).

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
| `GET /v1/agents`, `GET /v1/agents/:name` | answered with the workspace key, filtered to agents whose inbox the caller may write or read, or whose directory entry `relaycast:agent/<name>` it may read |
| `GET /v1/channels` | filtered to channels the caller may read |
| `POST /v1/channels` | `w` on `relaycast:channel/<name>` |
| `GET /v1/channels/:name`, `/messages`; `POST .../join` | `r` on the channel |
| `POST /v1/channels/:name/leave`, `/mute`, `/unmute` | self |
| `POST /v1/channels/:name/messages` | `w` on the channel (classifier as usual) |
| `GET /v1/messages/:id`, `/replies`, `/reactions`; `POST .../read`; `DELETE .../reactions/:emoji` | `r` on the message's channel; a DM message only for its two participants |
| `POST /v1/messages/:id/replies` | `w` on the message's channel; under a DM, only a participant, decided as `POST /v1/dm` to the other participant (`w` on `relaycast:inbox/<other>`) |
| `POST /v1/messages/:id/reactions` | `w` on the message's channel; refused under a DM |
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
  capabilities; every other field, such as `name`, `max_agents`, `tags`,
  `version`, `machine_id`, `origin_surface` and `provider` `{name,
  instance_id}`, passes through unchanged), `node.heartbeat` and
  `delivery.ack` for the agent itself;
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

### The delivery queue

Relaycast keeps a durable delivery queue per agent; relaygate serves it with
the caller's own upstream identity, filtered like everything else:

```
GET  /v1/deliveries?status=<queued|delivered|acked|failed|dead_lettered>&limit=<1..200>
POST /v1/deliveries/:id/ack
POST /v1/deliveries/:id/fail    {"error"?: string, "retryable"?: boolean}
POST /v1/deliveries/:id/defer   {"available_at": "<ISO-8601>", "reason"?: string}
Authorization: Bearer rg_...
```

Requests and responses are Relaycast's (`{ok, data}`; a delivery item is
Relaycast's delivery record plus its `message`). relaygate places each item by
its `channel_id`: a channel the caller may read is returned; a 1:1 DM is the
caller's own inbox (returned if it may read its inbox); anything else (a group
DM, an unknown channel, a channel it may not read) is never returned, and
relaygate marks it failed upstream (`error: "relaygate_denied"`,
`retryable: false`) so it isn't redelivered. `ack`, `fail` and `defer` act
only on the caller's own deliveries (Relaycast checks ownership) and answer
Relaycast's `404 delivery_not_found` for anyone else's.

### The sender's groups travel with the message

Every message relaygate forwards carries the sender's verified groups, so the
recipient knows who is asking and with what scope:

```
"data": {"relaygate": {"agent": "<name>", "groups": ["dev", "dev-trusted"]}}
```

relaygate removes any `relaygate` field the client sent, so it can't be forged.
`GET /v1/whoami` returns the same card for the caller.

### Who am I

```
GET /v1/whoami
Authorization: Bearer rg_...

200 {"agent_id": "ag_...", "name": "<name>", "gid": 11, "groups": [],
     "group_names": ["local"], "guest": false,
     "user_id": "<control user id>",
     "relaygate": {"agent": "<name>", "groups": ["local"]}}
```

It answers only for the caller's own token. `user_id` is present only for an
agent enrolled with a relay-control credential: for a device-enrolled agent
("Enrolling with a device token") the user the device token introspected as,
for a launched agent ("Launched agents") the launching person (the launch
credential's `sub`). It is the same `user_id` `POST /v1/register` returned,
recorded with the agent when it registered (so it survives a restart and
needs no introspection), and it doesn't change on re-registration or token
refresh, since only the same person gets the name back. An agent enrolled
with an enrollment key has no Control principal and no `user_id`. `guest:
true` appears on the `relaygate` card only for guests; `user_id` never does,
so it isn't stamped on what the agent sends.

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
becomes `https://<relaygate>/sessions` and the paths stay the same. For hosts
listed in `SESSIONS_HOSTS` (a deployment's history origin pointed at relaygate),
the same routes are served at the root, so clients keep their configured origin.
Uploads go to `SESSIONS_UPLOAD_URL` and reads to `SESSIONS_READ_URL` (both
default to `SESSIONS_URL`).

relaygate holds no Sessions credential of its own. A caller sends its rg_ token
in `X-Relaygate-Token` and its own Sessions credential (a device token for
uploads, a read token for reads) in `Authorization`; relaygate checks the rg_
principal and forwards that credential unchanged, so Sessions still records the
real uploader. `SESSIONS_TOKEN` is an optional service credential used only
for callers that send their rg_ token in `Authorization` and no Sessions
credential. Because callers hold real Sessions credentials, the gate is only as
strong as the network rule that Sessions accepts traffic from relaygate alone
(see "Tokens and the upstream credentials").

| Route | Check |
|---|---|
| `POST /sessions/v1/sessions/:id/turns` | `w` on the session; `sessionOwner` on the body and every turn is set to the agent |
| `POST /sessions/v1/delivery/batches` | the native delivery protocol (JSON, optionally `gzip` or `zstd`): `w` on every `records[].session_id`, all or nothing; a record without a session is refused; the original bytes and `Content-Encoding` are forwarded |
| `GET /sessions/v1/delivery/limits`, `GET .../delivery/admission`, `POST .../auth/token/refresh`, `POST .../onboarding/heartbeat`, `POST .../upload-consent` | passed through (no session content) |
| `POST /sessions/v1/delivery/sessions/selection` | `w` on every session it names (choosing what syncs) |
| `POST /sessions/v1/auth/token/revoke`, `GET /sessions/healthz` | no principal needed (revoking is always safe) |
| `POST /sessions/v1/ingest` | `w` on every session the batch names; all or nothing. Each record gets a `relaygate:agent:<name>` tag (client `relaygate:` tags are dropped) and, where it names one, `sessionOwner` set to the agent |
| `GET /sessions/v1/sessions` | filtered to sessions the caller may read; the cursor passes through; labeled sessions carry `relaygate` (see "Group labels") |
| `GET /sessions/v1/sessions/:id/{events,turns,metadata,thread,catalog,timing,analysis,brief,summary}` | `r` on the session; `metadata` and `catalog` of a labeled session carry `relaygate` |
| `GET /sessions/v1/events?session=<id>` | one `session`, `r` on it |
| `GET /sessions/v1/events?q=<text>` | transcript search, filtered to events of sessions the caller may read |
| `GET/PATCH /sessions/v1/sessions/:id/access` | runtime access policy, restricted to `sessionAccessAdmins` groups |
| `GET /sessions/v1/sessions/:id/access/history` | immutable runtime-policy history, restricted to `sessionAccessAdmins` groups |
| `GET /sessions/v1/relayfacts[/:topic]` | passed to the read API after normal relaygate/Control authentication |
| `GET /sessions/v1/coordination/{overlaps,advisories}` | passed to the read API after normal relaygate/Control authentication |
| `POST /sessions/v1/coordination/advisories/:id/ack` | read-plane acknowledgement passed to the read API; requires `rth:read`, not upload scope |

A write is decided before anything is recorded; the classifier sees every
forwarded field, not only `content`. New sessions are claimed in one
transaction only when the whole request is allowed, so a refused upload never
makes its sender an owner. A claim is never released, even if Sessions rejects
the upload: the uploader chose the session id and is the one who retries, and
releasing could hand a session another upload filled to a different group. A session override changes mode and ACL only, never the
owning group, which is what ceilings are checked against. Sessions that never came through relaygate have no owner and
are invisible through it. Other Sessions routes, including aggregate
reads across sessions (`/v1/sessions/users`, `/activity`, `/v1/digest/*`),
answer `404 relaygate_route_not_proxied`. Pit agents
run headless on Linux servers, so their sessions come from a headless uploader
on that server, authenticated with the agent's `rg_` token, not from the
desktop app.

### Signed upstream authorization

Network reachability is defense in depth, not the Sessions authorization
boundary. When `RELAYGATE_UPSTREAM_ASSERTION_KEY` and
`RELAYGATE_UPSTREAM_ASSERTION_KID` are set, relaygate adds
`X-Relaygate-Assertion` after it has allowed each proxied read or write. The
read API and ingest edge must hold the same current/previous key map and reject
an unsigned or invalid assertion on every content route.

The header is `v1.<base64url-json>.<base64url-hmac-sha256>`. The MAC input is
the ASCII prefix `relaygate-upstream-v1\n` followed by the payload segment
exactly as sent. Its JSON claims are:

```json
{
  "v": 1, "iss": "relaygate", "aud": "session-read-api", "kid": "current-1",
  "iat": 1800000000, "exp": 1800000030, "jti": "<uuid>",
  "method": "GET", "path": "/v1/events?session=s-1",
  "body_sha256": "<hex>", "credential_sha256": "<hex>",
  "principal": {"agent_id": "ag_...", "gid": 11, "groups": [22]},
  "access": "read", "session_ids": ["s-1"], "session_count": 1,
  "session_ids_sha256": "<hex>"
}
```

The path is the exact upstream pathname and query; the body hash covers the
exact forwarded bytes, including compressed delivery batches; and the
credential hash binds the proof to the forwarded `Authorization` value
without exposing that credential. Session scope is sorted and de-duplicated;
`session_count` and `session_ids_sha256` always bind its canonical JSON. At
most 16 ids and 2 KiB are also carried inline in `session_ids`; larger batches
use an empty inline array, keeping the assertion header bounded.
`aud` is `session-read-api` or `ingest-edge`, preventing cross-service replay
even when both services share the rotation key.
Single-session reads and writes name their sessions. Lists and transcript
search carry `access: "filter"` and an empty list because relaygate filters the
upstream page; permitted whole-workspace aggregates carry `aggregate`. The
administrative adoption scan signs every direct session-list page as a
`filter` read too, leaving no unsigned read-API path when verification is on.

The default lifetime is 30 seconds and the configurable range is 5 through
60. A verifier checks the MAC in constant time, selects the key by `kid`,
allows at most five seconds of future clock skew, checks expiry and maximum
lifetime, then recomputes every request binding. During rotation it accepts
the current and previous kid/key but relaygate signs only with the current
one. Assertions and credentials must not be logged. The assertion proves the
gate's decision; the upstream still validates the caller's ordinary Sessions
credential.

### Relayfacts and coordination

Gate-only history hosts also proxy the read API features under
`/v1/relayfacts` and `/v1/coordination`; otherwise an ingress route to
relaygate would turn a feature-disabled answer into an unrelated edge 404/503.
The allowlist is deliberately exact:

- `GET /v1/relayfacts` and `GET /v1/relayfacts/:topic`;
- `GET /v1/coordination/overlaps`;
- `GET /v1/coordination/advisories`;
- `POST /v1/coordination/advisories/:advisoryId/ack`.

They use the caller's forwarded Sessions credential, the same Control
principal mapping and `rth:read` check as session reads, and a read-API upstream
assertion when assertions are enabled. The acknowledgement is a read-plane
state change and therefore does not require `rth:sync`; relaygate applies an
8 KiB streaming body cap before buffering it. Feature flags,
workspace scoping, response status and request-body validation remain owned by
the read API. Every other path under either prefix gets
`404 relaygate_route_not_proxied` without reaching upstream.

### Group labels

A deployment can name its groups for people reading sessions, so a dashboard
can badge, say, every session the pit group owns. Labels are display only:
they grant nothing and change no decision. No group has a label unless the
policy gives it one.

```
"groupLabels": {"22": {"label": "pit", "description": "Agents inside the boundary"}}
```

Keys are gids in decimal, each one a group the policy defines. `label` is 1 to
24 characters (letters, digits, space, `.`, `_`, `-`; it starts with a letter
or digit and doesn't end in a space); `description` is optional, at most 200
characters, and is not sent to readers. Both the loader and
`POST /admin/v1/policy/validate` refuse anything else.

On reads that pass the check, relaygate adds the owning group and its label to
each session a labeled group owns:

- every session in `GET /sessions/v1/sessions`;
- the top-level object of `GET /sessions/v1/sessions/:id/metadata` and `.../catalog`.

```
{"sessionId": "...", ..., "relaygate": {"gid": 22, "label": "pit"}}
```

Nothing else changes: a session whose group has no label gets no `relaygate`
key, other views are untouched, and a single-session view without a label
passes byte for byte. The owner is never named. A `relaygate` key that comes
from Sessions itself is dropped, so a reader can trust that only relaygate
wrote it. A caller only ever sees the label of a session it may read, and a
session that never came through relaygate has no owning group, so no label.

### Runtime session access

An explicitly authorized group can restrict or relabel an already-owned
session without editing and republishing the whole operator policy. The
authorization is itself operator policy:

```json
"sessionAccessAdmins": {"gids": [33]}
```

Any principal whose primary or supplementary group is listed may manage a
session's runtime access. This is intended for a Control-mapped librarian
principal; a read token minted for a browser or agent-behalf MCP call may use
the endpoint, and the group check still applies. Named people are resolved by
Control into durable per-person groups before the call, so relaygate stores no
email, display name or other member identity.

```http
PATCH /sessions/v1/sessions/<id>/access
Authorization: Bearer <Control read token or rg_ token>
Content-Type: application/json

{
  "mode": "000",
  "acl": [{"gid": 101, "perm": "r"}, {"gid": 102, "perm": "r"}],
  "label": "restricted",
  "expectedVersion": 0,
  "reason": "sensitive"
}
```

`gid`, `mode`, `acl` and `label` are patch fields. The resulting complete
policy is stored in relaygate's database with a monotonically increasing
version. `expectedVersion` is optional; when present a stale edit gets `409`
with `currentVersion`. `label: null` removes the badge. Labels and gids use the
same validation as policy labels and ACLs.

Once present, the runtime policy replaces the session default and static
`sessionOverrides` entry. `resolveSession` therefore makes one decision for
single-session views (including `summary`), events, transcript search and
session lists. Runtime gid/label values also drive the trustworthy
`relaygate` badge. Writes are covered too; for a read-only restriction use
`mode: "000"` and `r` ACL entries as above.

A runtime `gid` changes the effective group but never erases the immutable
first-uploader group: ceilings are checked against both. Write classification
also snapshots the runtime version. If access changes while classification is
in flight, relaygate re-decides the whole request and never forwards a write
under the stale decision.

`GET .../access` returns the effective policy and its version. Every successful
change appends an immutable before/after row, including actor, timestamp,
version and the optional content-free reason; managers read it at
`GET .../access/history?after=<seq>&limit=<n>`. The ordinary operator audit log
also records the authorization decision and successful version change. Neither
log contains trace content.

## Control principals

Some callers hold only relay-control credentials: the desktop app uploads
sessions with its device token (`sh_at_…`), and the dashboard reads them with
Control-issued read tokens (`rth_at_read_…`, service tokens `rth_st_read_…`).
On Sessions routes, a request with one of those in `Authorization` and no
`X-Relaygate-Token` is a **Control principal**:

- **Device tokens** are introspected with relay-control
  (`POST /internal/v1/auth/introspect`, `RELAYCONTROL_INTROSPECT_SECRET`, `aud` =
  `SESSION_INGEST_AUDIENCE`), which answers with the user, org, workspace, live
  org role and scopes. Positive answers are reused for up to 15 s.
- **Read tokens** can't be introspected: only the read API's own table knows
  them. relay-control mints them by calling the read API's internal
  `/internal/v1/session-read/sessions` (and `/refresh`, `/service-tokens`); with
  relay-control's read API URL pointed at relaygate (a bare origin: relaygate's
  internal `SESSIONS_PORT` listener, which serves Sessions at its root),
  relaygate forwards those
  calls unchanged and records the hash of each minted token with the identity
  the mint named (and its role, when the mint carries one). The mint routes are
  never served on a public Sessions host, and are checked against
  `SESSIONS_INTERNAL_SECRET` when it is set. Successful refresh and revoke
  calls are mirrored into that local hash cache, so a rotated or revoked read
  credential cannot continue using relaygate-local management routes.

The policy maps them to groups; the first rule whose every given field matches
wins, and a user no rule matches is refused:

```
"controlPrincipals": [
  {"match": {"orgIds": ["<org>"], "roles": ["owner", "admin"]}, "gid": 33},
  {"match": {"orgIds": ["<org>"], "emails": ["<someone>@<domain>"]}, "gid": 22},
  {"match": {"orgIds": ["<org>"]}, "gid": 11}
],
"sessionAggregates": {"gids": [33]}
```

`match` takes `kinds` (`device`, `read`, `launch`, `hosted`), `clients` (hosted
only, see "Hosted participants"), `as`, `readerKinds`, `orgIds`,
`workspaceIds`, `roles`, `userIds` and `emails`. `as` says what the credential
stands for: `agent` when it enrols an agent at `POST /v1/register` (a device or
launch or hosted credential), `person` everywhere else (Sessions uploads and reads,
`/v1/check`, adoption). Rules without `as` match both. Put `as: ["person"]` on
rules that grant more than an agent should have (admins), so the agents those
people enrol land in an agent rule instead.

`as` separates what a credential enrols, not who presents it: relaygate can't
tell whether a person or an agent sends a bearer token. An agent that can reach
its person's device token (it sits on the same laptop) can drop
`X-Relaygate-Token` and be served as that person, and relay-control also mints
read tokens for agents (agent-behalf MCP reads) and desktops. So grant
person-only reads to read tokens minted for a dashboard browser session:
`readerKinds`.

`readerKinds` (`browser`, `device`, `mcp`) matches a read token by how the
reader authenticated to relay-control when it was minted: `browser` a
cookie-authenticated dashboard session, `device` a desktop or CLI bearer, `mcp`
an agent-behalf read. relay-control sets `reader_kind` in the internal mint
request body (and on refresh); relaygate keeps it with the token's hash and
strips it before forwarding the mint to the read API. A token minted without
it, or with an unknown value, matches no `readerKinds` rule, and neither does
any device or launch credential. For example, every person reads the pit from
the dashboard while their agents stay local:

```
"groups": [..., {"gid": 44, "name": "people"}],
"sessionDefaults": [{"gid": 22, "mode": "660", "acl": [{"gid": 33, "perm": "r"}, {"gid": 44, "perm": "r"}]}, ...],
"controlPrincipals": [
  {"match": {"orgIds": ["<org>"], "emails": ["<admin>@<domain>"], "as": ["person"]}, "gid": 33},
  {"match": {"orgIds": ["<org>"], "as": ["agent"]}, "gid": 11},
  {"match": {"orgIds": ["<org>"], "kinds": ["read"], "readerKinds": ["browser"]}, "gid": 44},
  {"match": {"orgIds": ["<org>"]}, "gid": 11}
]
```

The admin's own device token still reads as 33 on Sessions, for whatever can
reach it. A rule may also set `namePrefix`, which limits the
agent names that person's desktop may enrol (see "Enrolling with a device
token"). A read token minted without a role never matches a rule
that needs one; without an email it uses the email relay-control last reported
for that user (from a device-token introspection), and otherwise doesn't match
an email rule.

Uploads need a device token with `rth:sync`; a read token, or a device token
without it, only reads, and reads need `rth:read`. The name prefix `ctl:` is
reserved: no enrollment key registers it, and a registered agent never stands
for a Control user. Each Control user becomes the relaygate principal
`ctl:<userId>`, which owns the sessions it uploads and appears in the audit
log; its credential is forwarded to Sessions unchanged, so Sessions still
records the real person.

Aggregate reads that span every session (`/v1/sessions/users`, `/activity`,
`/summaries/activity`, `/output`, `/titles`, `/v1/delivery/records`,
`/v1/digest/*`) are served
only to the groups in `sessionAggregates`, and never to a principal under any
ceiling (an aggregate may include groups it must not see). CORS preflights are passed to the
read API unauthenticated, and the read API's CORS and workspace headers come
back unchanged; relaygate's own refusals carry CORS headers for the origins in
`SESSIONS_CORS_ORIGINS`, so a browser sees the real status.

## Adopting existing sessions

Sessions uploaded before relaygate was in front of Sessions have no relaygate
owner, so they are invisible through it. An operator adopts them once, at the
switch:

```
POST /admin/v1/sessions/adopt?dryRun=1
Authorization: Bearer <admin token>
{"readToken": "rth_st_read_...", "orgId": "<org>", "workspaceId": "<ws>"}
```

relaygate pages the read API's session list with that read service token,
takes each unowned session's uploader (its first `userIds` entry), maps that
user through `controlPrincipals` (by org, user id, and email if relaygate has
seen it; role isn't known here), and claims the session as `ctl:<userId>` in
that rule's group. The report lists what it adopted, what was already owned,
sessions with no uploader, and uploaders no rule matches (those stay unowned).
`dryRun` only reports; without it the adoption is applied and audited
(`session.adopt`). Rerunning it is safe. A run lists at most `maxPages` pages
(default 500); if it stops there, the report has `truncated: true` and a
`nextCursor` to pass back as `cursor`.

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

`resource` is a stream (`{"kind": "stream", "id"}`) or a session (`{"kind":
"session", "id", "gid"?}`: a recorded session is looked up; otherwise `gid` is
the group of its hypothetical first uploader). `as` is a registered agent (`{"agent": "<name>"}`), a new agent enrolled with
a key (`{"key": "<id>", "name"?}`), or bare groups (`{"gid": 44, "groups":
[]}`), or a relay-control user mapped through `controlPrincipals`
(`{"control": {"userId", "orgId", "email"?, "role"?, "workspaceId"?, "kind"?,
"readerKind"?, "as"?}}`; by default a person on the dashboard, `kind: "read"`
with `readerKind: "browser"`; `kind: "device", as: "agent"` explains the
agents their desktop enrols; the first step names the matching rule by index).
A body with `cases` instead runs a list of expected decisions
(`"expect": "allow" | "deny"`, optionally `"classified"`) and reports which
fail, so a drafted policy can carry its own tests. An invalid draft answers
`400 relaygate_bad_policy` with the reason. Nothing is applied and nothing is
audited as a decision.

The same check runs offline: `relaygate-explain --policy <file> --as
key:vendor-guest --op w --stream <id>`, or `--cases <file>`, which exits `1`
when any case fails (see `examples/cases.pit.json`).

## Admin API for relay-control

relay-control (or an operator) calls these with `RELAYGATE_ADMIN_TOKEN`;
without it they answer 404.

- `POST /admin/v1/policy/validate` `{"policy": {...}}`: `{"ok": true, "hash"}`
  or `{"ok": false, "errors": [{"path", "message"}]}`, by the same validator
  relaygate loads every policy with. relay-control runs it before publishing a
  version.
- `GET /admin/v1/policy/status`: where the policy comes from and what is in
  force (see "Who decides, who enforces").
- `GET /admin/v1/keys`: each enrollment key in the policy in force, `{id, gid,
  groups, namePrefix, guest, revoked, expiresAt, usable, agents,
  activeTokens, lastUsedAt}`, never the key or its hash. `lastUsedAt` is the
  latest registration with the key or request by one of its agents (recorded
  at most once a minute per agent).
- `POST /admin/v1/explain` (above) and `GET /admin/v1/audit` (below).

## Audit

relaygate records every decision: who, what resource, which op, allowed or
denied, and by which stage (mode or classifier). It never records message
content.

Each row also carries the `policy_version` in force (the first 12 hex digits
of the sha256 of the parsed policy), so a policy change is visible in the log.
`/readyz` reports the current version.

```
GET /admin/v1/audit?after=<seq>&agent=<name>&limit=<n>
Authorization: Bearer <admin token>

200 {"policy_version": "3f1c...", "rows": [{"seq": 41, "at": "...",
     "agent_name": "local-a", "action": "dm.send", "op": "w",
     "resource_kind": "stream", "resource_id": "relaycast:inbox/pit-a",
     "decision": "allow", "stage": "classifier", "reason": "...",
     "policy_version": "3f1c..."}]}
```

Rows come oldest first after `after`; `limit` is at most 1000.

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
