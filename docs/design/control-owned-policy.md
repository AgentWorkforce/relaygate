# Control-owned policy, guest access and group admin

Status: design, relaygate side in progress. Owners: relaygate (this repo), relay-control (layered-control), relay-web (dashboard).

## Goal

Today the policy is a JSON file (a ConfigMap) that an operator edits by hand. Target:

- relay-control owns the policy. Org owners and admins edit it in the dashboard: groups, who maps to which group (`controlPrincipals`), stream and session defaults and ACLs, overrides, ceilings, the classifier, and guest enrollment keys.
- Guest and contractor access becomes a dashboard flow. An admin creates a key with a group, an expiry and a name prefix, sees it once, and can list it (with last use) and revoke it.
- relaygate pulls the policy from relay-control. Each version is numbered and authenticated, and cached on disk. relaygate keeps the last good version when an update fails and fails closed when it has none.
- "May X do Y, and why?" (explain) is available in the dashboard, including against a draft before it is published.

Unchanged:

- relaygate enforces and relay-control decides, as described in contract.md, "Who decides, who enforces".
- The policy schema stays the same. relay-control stores and serves exactly what `parsePolicy` accepts, so the file, the API and the explain CLI share one format and one validator.
- File mode stays for installs without relay-control and for tests. Set exactly one source: `RELAYGATE_POLICY` (file) or `RELAYCONTROL_POLICY_URL` (pull).

## relaygate

### Pulling the policy

- `RELAYCONTROL_POLICY_URL` (e.g. `http://<control>/internal/v1/relaygate/policy`) and `RELAYCONTROL_POLICY_SECRET` (at least 32 characters, separate from the introspection secret).
- relaygate polls every `RELAYGATE_POLICY_RELOAD_MS` (default 5000):

  ```
  GET <url>
  Authorization: Bearer <secret>
  If-None-Match: "<version in force>"
  ```

  The answer is either 304 or 200 with this body:

  ```json
  {"version": 42, "updatedAt": "2026-11-16T04:00:00Z", "policy": { ...the policy file shape... }}
  ```

  It carries the header `X-Relaycontrol-Signature: v1=<hex HMAC-SHA256(secret, raw body)>`.

- relaygate applies a new version only if all of these hold:
  - the signature verifies (constant-time);
  - the body parses with `parsePolicy`;
  - `version` is greater than the version in force (a rollback is a new, higher version);
  - the policy file shape is unchanged.

  Otherwise it keeps the version in force, logs the reason and reports it in status.
- Each applied version is written to the database (`policy_cache`: version, body, signature, fetched_at). At startup relaygate uses the cached copy until relay-control answers. Without a cached copy, and before the first good pull, relaygate fails closed:
  - every route except `/healthz` answers `503 relaygate_unavailable`;
  - `/readyz` stays 503;
  - nothing is forwarded.
- relay-control being down has no effect on enforcement: relaygate keeps the version it has.
- A change takes effect within one poll interval. The guest-key sweep runs after each apply, so a revoked key's tokens end on that poll.
- The audit `policy_version` becomes `c<version>-<hash12>` for pulled policies. File policies keep `<hash12>`.

### Admin API (for relay-control; `RELAYGATE_ADMIN_TOKEN`)

- `GET /admin/v1/policy/status`: `{source: "file"|"control", version, hash, appliedAt, lastFetchAt, lastError?, lastRejected?: {version, reason}}`. The dashboard shows "relaygate is on version N" from this.
- `POST /admin/v1/policy/validate` `{policy}` returns `{ok: true, hash}` or `{ok: false, errors: [...]}`. This is the same validator relaygate applies on pull. relay-control calls it before publishing, so an invalid edit never becomes a version.
- `POST /admin/v1/explain` gains:
  - `policy` (optional): explain against a draft instead of the version in force.
  - `as: {control: {userId, orgId, email?, role?, workspaceId?, kind: "device"|"read"|"launch", readerKind?, as?: "person"|"agent"}}`: explain for a person or a desktop agent, not only a registered agent. The answer names the `controlPrincipals` rule that matched (by index) along with the existing steps.
- `GET /admin/v1/keys`: per enrollment key in the policy, `{id, guest, gid, expiresAt, revoked, lastUsedAt, agents, activeTokens}`.
  - `lastUsedAt` is the most recent registration with the key or call by one of its agents. It is tracked per agent (`agents.last_seen_at`, written at most once a minute per agent).
  - Keys relay-control created but the policy no longer lists are omitted.

### Not in relaygate

relaygate never generates or stores enrollment keys in plaintext. relay-control generates a key, shows it once, and puts only its sha256 in the policy, as the file does today.

## relay-control (layered-control)

### Storage (new migration)

- `relaygate_policy_versions`:
  - columns: `version` (bigserial, primary key), `body` (jsonb, the policy without generated keys), `created_by` (user id), `created_at`, `comment`, `source_version` (set by rollback);
  - append-only; the current policy is the highest version.
- `relaygate_enrollment_keys`:
  - columns: `id` (text, unique, not `control`/`device:*`/`launch:*`), `label`, `gid`, `groups` (int[]), `sha256`, `name_prefix`, `guest` (bool), `expires_at`, `revoked_at`, `created_by`, `created_at`;
  - key material is never stored, only the sha256.
- The served policy is `body` from the highest version, with `enrollmentKeys` built from `relaygate_enrollment_keys`:
  - `revoked: true` when `revoked_at` is set;
  - `expiresAt` from `expires_at`.

  Creating or revoking a key creates a new policy version, so relaygate sees the change on its next poll.

### Internal API (relaygate pulls)

- `GET /internal/v1/relaygate/policy`:
  - authenticated with `RELAYCONTROL_POLICY_SECRET`;
  - returns the body above, signed;
  - honours `If-None-Match` (304);
  - never served on a public route.

### Dashboard API (relay-web calls; org owner or admin only, cookie session; every change audited)

- `GET /api/v1/relaygate/policy`: the current version, its body, and relaygate status (proxied from `/admin/v1/policy/status`).
- `GET /api/v1/relaygate/policy/versions`, `GET .../versions/{v}`: history and diff.
- `PUT /api/v1/relaygate/policy` `{body, baseVersion, comment}`:
  - optimistic concurrency: 409 if `baseVersion` isn't current;
  - validates with relaygate's `/admin/v1/policy/validate`, then writes a new version;
  - refuses when relaygate can't validate (a 503 with "relaygate unreachable"; nothing is saved).
- `POST /api/v1/relaygate/policy/rollback` `{toVersion}`: copies that version's body into a new version.
- `POST /api/v1/relaygate/keys` `{label, gid, groups?, namePrefix?, guest, expiresAt}`:
  - generates the key (`rg_ek_` plus 32 random bytes, base64url) and stores only its sha256;
  - creates a new policy version and answers `{id, key}` once.
- `GET /api/v1/relaygate/keys`: rows merged with relaygate's `/admin/v1/keys` (last used, agents, active tokens).
- `POST /api/v1/relaygate/keys/{id}/revoke`: sets `revoked_at` and creates a new policy version.
- `POST /api/v1/relaygate/explain` `{as, op, resource, draft?}`: proxies relaygate's `/admin/v1/explain`, with the draft body when previewing.

### Config

- `RELAYGATE_ADMIN_URL` and `RELAYGATE_ADMIN_TOKEN` (relay-control calls relaygate's admin API in-cluster).
- `RELAYCONTROL_POLICY_SECRET` (shared with relaygate).
- Off unless `SELFHOST_RELAYGATE_PUBLIC_URL` is set.

### Bootstrapping

The first version is imported from the current ConfigMap (`POST /api/v1/relaygate/policy/import`, owner only, once), so a deployment switches from file to pull with no policy change. The key sha256s in the file become rows with `label` = id and no key material.

## relay-web (dashboard screens, under Settings → Gate)

1. **Overview**: the version in force at relaygate against the latest saved version, the last error or rejection, and a link to history.
2. **Groups**: list, add and rename. Delete is blocked while referenced; the validator says where.
3. **People and admins** (`controlPrincipals`): an ordered rule list with drag to reorder, since the first match wins. Each rule takes:
   - match fields: emails, user ids, roles, kinds, readerKinds, as;
   - a group and extra groups;
   - a name prefix.

   The screen warns about rules that can never match because an earlier rule covers them.
4. **Streams and sessions**: tables of prefix defaults, overrides and session defaults. Each row has an owner group, mode (read and write toggles for owner, group and other) and ACL chips (group plus r, w or rw).
5. **Ceilings**: per group, the groups it may never touch.
6. **Guest access**:
   - Create a key: label, group, extra groups, name prefix, expiry (required for guests) and a guest flag. The key is shown once with a copy button and a "this won't be shown again" notice.
   - The list shows group, expiry, last used, agents and active tokens.
   - Revoke asks for confirmation and states what it does:
     - for a guest key, every token issued from it ends on relaygate's next poll (within seconds);
     - for an ordinary key, it stops new enrolments only, and agents already enrolled keep working (contract.md, "Guests").

     Contractor and guest keys created on this screen are always guest keys, so revoking one always ends access.
7. **Explain**: "may [person or agent] [read or write] [stream or session id]". Shows the decision, the steps and the matching rule. "Preview with my unsaved changes" sends the draft.
8. **History**: versions with author, time and comment; a diff against the previous version; rollback.

Every edit screen saves through `PUT /policy` with the base version. Invalid drafts show relaygate's validator errors inline. A raw JSON editor is available for owners and validated the same way.

## PRs

| # | Repo | PR | Depends on |
|---|------|----|------------|
| R1 | relaygate | Policy pull from relay-control: signed, versioned, cached, last good, fail closed, `/admin/v1/policy/status` | none |
| R2 | relaygate | `/admin/v1/policy/validate`, explain with `policy` draft and `as.control`, `/admin/v1/keys` with last use | none |
| C1 | relay-control | Storage, internal policy route (signed), import, history, rollback | R1 for an end-to-end test |
| C2 | relay-control | Keys API (generate, show once, revoke), explain and status proxies | C1, R2 |
| W1 | relay-web | Overview, Groups, People and admins, Streams and sessions, Ceilings, History | C1 |
| W2 | relay-web | Guest access, Explain | C2 |
| I1 | infra | chart: `RELAYCONTROL_POLICY_URL`/`_SECRET` for relaygate, `RELAYGATE_ADMIN_URL`/`_TOKEN` for relay-control, ConfigMap import, then drop the ConfigMap | R1, C1 |

## Estimate

- relaygate R1 + R2: about 1.5 days.
- relay-control C1 + C2: about 3 days.
- relay-web W1 + W2: about 4 days.
- infra I1: about 0.5 day.

Run in parallel, about 1 to 1.5 weeks of wall time to a dashboard-edited policy on the POC, plus review.

## Open questions for Khaliq

- Who may edit: org owners only, or owners and admins? This design assumes owners and admins, with import, raw JSON and rollback limited to owners.
- Approval for risky edits (two-person rule) on changes that widen access to a protected group. This design has none: every change is versioned, audited and reversible.
- Whether guest keys must always expire. This design requires an expiry, capped by a configurable maximum (default 30 days).
