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
    }),
  ),
  streamDefaults: z
    .array(
      z.object({
        prefix: z.string().min(1),
        gid: z.number().int().nonnegative(),
        mode: Mode,
        classify: z.boolean().default(false),
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
      }),
    )
    .default([]),
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
  ].filter((r) => !gids.has(r.gid));
  if (unknown.length > 0) {
    throw new Error(`policy names groups it doesn't define: ${unknown.map((u) => `${u.where} (gid ${u.gid})`).join(", ")}`);
  }
  for (const rule of policy.classifier.rules) new RegExp(rule.pattern, rule.flags);
  return policy;
}

export function loadPolicyFile(path: string): Policy {
  return parsePolicy(JSON.parse(readFileSync(path, "utf8")));
}
