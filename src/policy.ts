import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { z } from "zod";

/**
 * The operator's policy. In production relay-control is the source of truth
 * (see docs/contract.md, "Who decides, who enforces"); until its API exists,
 * relaygate reads the same shape from a JSON file.
 */

const Mode = z
  .string()
  .regex(/^[0246]{3}$/, "mode is three octal digits using only 4 (read) and 2 (write); 1 is reserved");

const Gid = z.number().int().nonnegative();

/** Extra group entries that only add access (docs/contract.md, "Access lists"). */
export const AclSchema = z.array(z.object({ gid: Gid, perm: z.enum(["r", "w", "rw"]) })).default([]);

const Sha256 = z.string().regex(/^[0-9a-f]{64}$/, "sha256 as 64 lowercase hex characters");

export const PolicySchema = z.object({
  groups: z
    .array(z.object({ gid: z.number().int().nonnegative(), name: z.string().min(1) }))
    .min(1),
  enrollmentKeys: z.array(
    z.object({
      id: z.string().min(1),
      gid: z.number().int().nonnegative(),
      /** Supplementary groups every agent enrolled with this key also belongs to. */
      groups: z.array(z.number().int().nonnegative()).default([]),
      /** sha256 of the enrollment key; the key itself never appears in the policy. */
      sha256: Sha256,
      namePrefix: z.string().min(1).optional(),
      revoked: z.boolean().default(false),
      /** After this instant the key enrolls no one (and, for a guest key, its tokens stop working). */
      expiresAt: z.iso.datetime({ offset: true }).optional(),
      /** A guest key: revoking or expiring it ends every token issued from it, and its agents carry `guest: true`. */
      guest: z.boolean().default(false),
    }),
  ),
  streamDefaults: z
    .array(
      z.object({
        prefix: z.string().min(1),
        gid: z.number().int().nonnegative(),
        mode: Mode,
        classify: z.boolean().default(false),
        acl: AclSchema,
      }),
    )
    .default([]),
  streamOverrides: z
    .array(
      z.object({
        id: z.string().min(1),
        gid: z.number().int().nonnegative(),
        mode: Mode,
        classify: z.boolean().default(false),
        acl: AclSchema,
      }),
    )
    .default([]),
  /** Mode and ACL for sessions, by the owning (first uploader's) group. A group without an entry gets 600. */
  sessionDefaults: z.array(z.object({ gid: Gid, mode: Mode, acl: AclSchema })).default([]),
  /**
   * Per-session changes, e.g. sharing one session with a guest: `{"id": "...", "acl": [{"gid": <gid>, "perm": "r"}]}`.
   * An override can't move a session to another group: its owning group is what ceilings are checked against.
   */
  sessionOverrides: z.array(z.object({ id: z.string().min(1), mode: Mode.optional(), acl: AclSchema }).strict()).default([]),
  /**
   * relay-control users without an rg_ token (the desktop app's device token, dashboard read tokens), mapped to
   * groups: the first rule whose every given field matches wins; no match means refused.
   */
  controlPrincipals: z
    .array(
      z.object({
        match: z
          .object({
            kinds: z.array(z.enum(["device", "read", "launch"])).min(1).optional(),
            /**
             * What the credential stands for here: "agent" when it enrols an agent at /v1/register (a device or launch
             * credential), "person" everywhere else (Sessions, /v1/check). Lets the same user read more as a person
             * than the agents they enrol.
             */
            as: z.array(z.enum(["person", "agent"])).min(1).optional(),
            /**
             * Read tokens only: how the reader authenticated to relay-control when it minted the token ("browser" a
             * dashboard cookie session, "device" a desktop/CLI bearer, "mcp" an agent-behalf read). A token minted
             * without one, and every device or launch credential, matches no rule that sets this.
             */
            readerKinds: z.array(z.enum(["browser", "device", "mcp"])).min(1).optional(),
            orgIds: z.array(z.string().min(1)).min(1).optional(),
            workspaceIds: z.array(z.string().min(1)).min(1).optional(),
            roles: z.array(z.enum(["owner", "admin", "member"])).min(1).optional(),
            userIds: z.array(z.string().min(1)).min(1).optional(),
            emails: z.array(z.string().min(3)).min(1).optional(),
          })
          .strict()
          .default({}),
        gid: Gid,
        groups: z.array(Gid).default([]),
        /** Agent names this person's desktop may enrol (POST /v1/register with a device token). */
        namePrefix: z.string().min(1).optional(),
      }),
    )
    .default([]),
  /** Agent name prefixes no one may enrol at /v1/register (e.g. names a control plane registers server-side). */
  reservedNamePrefixes: z.array(z.string().min(1)).default([]),
  /**
   * Each relay-control user's one person identity: the name `<prefix><first hashLength hex of sha256(userId)>`, which
   * only that user may enrol (with their device token, from any number of computers, each with its own recovery
   * proof), whatever their rule's namePrefix. No one else may enrol a name with this prefix.
   */
  personNames: z.object({ prefix: z.string().min(1), hashLength: z.number().int().min(8).max(64).default(16) }).strict().optional(),
  /** Who may read Sessions aggregates that span every session (per-person usage, activity, digests). */
  sessionAggregates: z.object({ gids: z.array(Gid).default([]) }).default({ gids: [] }),
  /** Per group, the groups whose resources it may never touch, whatever the mode or ACL says. */
  ceilings: z.array(z.object({ gid: Gid, never: z.array(Gid).min(1) })).default([]),
  classifier: z
    .object({
      rules: z
        .array(z.object({ id: z.string().min(1), pattern: z.string().min(1), flags: z.string().default("i") }))
        .default([]),
      model: z
        .object({
          enabled: z.boolean().default(false),
          model: z.string().default("claude-opus-5-5"),
          effort: z.enum(["low", "medium", "high"]).default("low"),
          timeoutMs: z.number().int().positive().default(8000),
          /** Free text the operator adds to the classifier's instructions (what counts as sensitive here). */
          guidance: z.string().default(""),
        })
        .default({ enabled: false, model: "claude-opus-5-5", effort: "low", timeoutMs: 8000, guidance: "" }),
    })
    .default({
      rules: [],
      model: { enabled: false, model: "claude-opus-5-5", effort: "low", timeoutMs: 8000, guidance: "" },
    }),
});

export type Policy = z.infer<typeof PolicySchema>;

export function parsePolicy(raw: unknown): Policy {
  const policy = PolicySchema.parse(raw);
  const gids = new Set(policy.groups.map((g) => g.gid));
  const unknown = [
    ...policy.enrollmentKeys.flatMap((k) =>
      [k.gid, ...k.groups].map((gid) => ({ where: `enrollment key ${k.id}`, gid })),
    ),
    ...policy.streamDefaults.map((d) => ({ where: `stream default ${d.prefix}`, gid: d.gid })),
    ...policy.streamOverrides.map((o) => ({ where: `stream override ${o.id}`, gid: o.gid })),
    ...[...policy.streamDefaults.map((d) => ({ where: `stream default ${d.prefix}`, acl: d.acl })),
      ...policy.streamOverrides.map((o) => ({ where: `stream override ${o.id}`, acl: o.acl }))].flatMap((x) =>
      x.acl.map((e) => ({ where: `${x.where} acl`, gid: e.gid })),
    ),
    ...policy.sessionDefaults.flatMap((d) => [d.gid, ...d.acl.map((e) => e.gid)].map((gid) => ({ where: `session default for ${d.gid}`, gid }))),
    ...policy.sessionOverrides.flatMap((o) =>
      o.acl.map((e) => ({ where: `session override ${o.id}`, gid: e.gid })),
    ),
    ...policy.controlPrincipals.flatMap((rule, i) => [rule.gid, ...rule.groups].map((gid) => ({ where: `control principal rule ${i}`, gid }))),
    ...policy.sessionAggregates.gids.map((gid) => ({ where: "sessionAggregates", gid })),
    ...policy.ceilings.flatMap((c) => [c.gid, ...c.never].map((gid) => ({ where: `ceiling for ${c.gid}`, gid }))),
  ].filter((r) => !gids.has(r.gid));
  if (unknown.length > 0) {
    throw new Error(`policy names groups it doesn't define: ${unknown.map((u) => `${u.where} (gid ${u.gid})`).join(", ")}`);
  }
  // `device:<userId>`, `launch:<userId>` and `control` mark agents relaygate enrols from relay-control identities; no policy key may use them.
  for (const k of policy.enrollmentKeys) {
    if (k.id === "control" || k.id.startsWith("device:") || k.id.startsWith("launch:")) {
      throw new Error(`enrollment key id ${k.id} is reserved (control, device:*, launch:*)`);
    }
  }
    // A key can't put an agent into a group its own ceiling forbids: the ceiling would always win, so it's a mistake.
  for (const k of policy.enrollmentKeys) {
    const mine = [k.gid, ...k.groups];
    for (const c of policy.ceilings.filter((c) => mine.includes(c.gid))) {
      const clash = c.never.find((g) => mine.includes(g));
      if (clash !== undefined) {
        throw new Error(`enrollment key ${k.id} enrolls into gid ${clash}, which the ceiling for gid ${c.gid} forbids`);
      }
    }
  }
  for (const rule of policy.classifier.rules) new RegExp(rule.pattern, rule.flags);
  return policy;
}

const versions = new WeakMap<Policy, string>();

/** A short, stable id for a parsed policy: the first 12 hex digits of the sha256 of its canonical JSON. */
export function policyVersion(policy: Policy): string {
  let v = versions.get(policy);
  if (!v) {
    v = createHash("sha256").update(JSON.stringify(policy)).digest("hex").slice(0, 12);
    versions.set(policy, v);
  }
  return v;
}

/** Names a policy's version as its source knows it (e.g. relay-control's number); audit rows record this. */
export function labelPolicyVersion(policy: Policy, label: string): void {
  versions.set(policy, label);
}

export type EnrollmentKey = Policy["enrollmentKeys"][number];

/** The person identity name for a relay-control user, if the policy names them (see `personNames`). */
export function personNameFor(policy: Policy, userId: string): string | undefined {
  const p = policy.personNames;
  return p ? `${p.prefix}${createHash("sha256").update(userId).digest("hex").slice(0, p.hashLength)}` : undefined;
}

/** Whether the key can still enroll agents at `now` (milliseconds since the epoch). */
export function keyUsable(key: EnrollmentKey, now: number): boolean {
  return !key.revoked && (key.expiresAt === undefined || Date.parse(key.expiresAt) > now);
}

export function loadPolicyFile(path: string): Policy {
  return parsePolicy(JSON.parse(readFileSync(path, "utf8")));
}
