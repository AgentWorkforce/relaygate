# relaygate contract

Status: draft, v0. This is the contract that clients (agents, the Slack
bridge, MCP servers) and relaygate build against. Anything marked **open** is
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

## Principals and groups

- A **principal** is an agent, or a human reached through a bridge (for
  example a Slack user).
- A **group** is a number (`gid`). Every principal is in exactly one group.
- A principal's group is set when it registers and does not change. Moving an
  agent to another group means registering a new agent.

Example deployment with two groups:

| gid | Name | Who |
|---|---|---|
| 11 | local | Agents on people's machines |
| 22 | pit | Agents that may see regulated data (PII under a BAA), running headless on servers; humans in Slack |

Group numbers and names are per deployment. relaygate has no built-in groups.

## Resources

relaygate guards two kinds of resource:

| Kind | Examples | Read means | Write means |
|---|---|---|---|
| `chat` | a channel, a DM inbox, a bridged Slack conversation | list and fetch messages | post a message or reply |
| `sessions` | a session transcript and its events | list, search and fetch it | upload or append to it |

Every resource has:

- `owner`: the principal that created it;
- `gid`: the owning group, which defaults to the owner's group;
- `mode`: three octal digits for owner, group and other, in that order.

Each digit is a sum of `4` (read) and `2` (write). `1` is reserved. So `6` is
read and write, `4` is read only, `2` is write only and `0` is nothing.

A DM is a write to the recipient's **inbox**, a `chat` resource owned by the
recipient. Whether A may DM B is therefore decided by B's inbox mode, and
whether B may answer is decided by A's inbox mode.

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

## Default modes for the pit deployment

These defaults implement the rules "a local agent can message a pit agent, a
pit agent can't answer an agent outside the pit, pit agents can read
everything, local agents only read sessions outside the pit, and only the pit
writes to Slack":

| Resource | gid | Mode | Pit (22) can | Local (11) can |
|---|---|---|---|---|
| Local chat (channels, local inboxes) | 11 | `664` | read | read, write |
| Pit chat (channels, pit inboxes) | 22 | `662` | read, write | write in, not read back |
| Slack conversations | 22 | `660` | read, write | nothing |
| Local sessions | 11 | `664` | read | read, write |
| Pit sessions | 22 | `660` | read, write | nothing |

Two deliberate choices in this table:

- **Pit agents only read local sessions.** With write access a pit agent could
  copy regulated data into a session that local agents can read, bypassing
  every chat rule.
- **Local agents can't upload into pit sessions.** **Open:** the original matrix
  gives local agents write-only access (`662`). That is only needed if local
  agents hand work to the pit as sessions rather than as messages.

A deployment can set other modes per resource. A resource's mode can only be
changed by its owner or by a relaygate admin, and the change is audited.

## Registration

An agent registers once, through relaygate, with an **enrollment key**. Each
enrollment key belongs to one group, so the key decides the group and the
agent can't pick its own.

```
POST /v1/register
Authorization: Bearer <enrollment key>
{"name": "slack-c0123-1731600000.123"}

200
{"agent_id": "...", "gid": 22, "token": "rg_..."}
```

After that the agent is in its group and every call it makes is checked.
Nothing else is configured per agent.

- Enrollment keys are created by a relaygate admin, one or more per group, and
  can be revoked. Revoking a key stops new registrations, not existing agents.
- **Open:** how humans bridged from Slack are represented: as principals the
  bridge registers, or as the bridge itself acting in group 22.

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

For clients, the change is a base URL. The Slack bridge and the MCP server set
their Relaycast and Sessions base URLs to relaygate and use the `rg_` token.
The API paths are unchanged.

## Reads and lists

A list or search returns only resources the caller may read. relaygate applies
that filter, either by narrowing the upstream query or by filtering the
response, so Relaycast and Sessions need no group support.

**Open:** filtering after the fact breaks pagination and counts. The Sessions
API likely needs a filter parameter that relaygate sets (for example "only
these gids"), which keeps it unaware of what the gids mean.

## Session uploads

A session is owned by the uploader and takes the uploader's group. Pit agents
run headless on Linux servers, so their sessions come from a headless uploader
on that server, authenticated with the agent's `rg_` token, not from the
desktop app.

## The classifier

The mode check runs first. The classifier only sees requests the mode bits
allowed, and only those that cross a group boundary:

- a write into another group's resource (for example a local agent messaging a
  pit agent);
- any post to Slack.

Request:

```
{"from": {"agent_id": "...", "gid": 11}, "op": "w",
 "resource": {"id": "...", "kind": "chat", "gid": 22},
 "content": "<message text>"}
```

Response: `{"decision": "allow" | "deny", "reason": "..."}`.

- A `deny` is answered with `403` and `{"error":"relaygate_classified"}`, and
  nothing reaches upstream.
- If the classifier errors or times out, the request is denied.
- The classifier is pluggable: a model, rules or both. **Open:** the default
  classifier and its latency budget.

## Audit

relaygate records every decision: who, what resource, which op, allowed or
denied, and by which stage (mode or classifier). It never records message
content.

## Open questions

- Local agents writing into pit sessions (`662` or `660`).
- How Slack humans are represented as principals.
- The Sessions API filter parameter for lists and search.
- The default classifier and its latency budget.
- Whether a principal ever needs more than one group.
- What, if anything, the `1` bit means.
