/** The deterministic check from docs/contract.md, "The check". */

export type Op = "r" | "w";
export type Perm = "r" | "w" | "rw";

export interface Principal {
  agentId: string;
  /** Relay-control person behind this principal, including an agent enrolled/hosted for that person. */
  userId?: string;
  /** Primary group, set at registration. */
  gid: number;
  /** Supplementary groups, from the operator's policy. */
  groups: readonly number[];
}

export interface AclEntry {
  gid: number;
  perm: Perm;
}

export interface UserAclEntry {
  userId: string;
  perm: Perm;
}

export interface Ceiling {
  /** The group the ceiling applies to. */
  gid: number;
  /** Groups whose resources it may never touch. */
  never: readonly number[];
}

export interface Guarded {
  /** agent_id of the owner, or null when the resource comes from a policy default or override. */
  owner: string | null;
  gid: number;
  /** Three octal digits: owner, group, other. */
  mode: string;
  /** Extra group entries that only add access (POSIX-ACL style). */
  acl?: readonly AclEntry[];
  /** Per-person grants. Agents enrolled or hosted for the named Control user inherit the grant. */
  users?: readonly UserAclEntry[];
  /** Additional immutable resource groups whose ceilings still apply after a runtime relabel. */
  ceilingGids?: readonly number[];
}

const BIT: Record<Op, number> = { r: 4, w: 2 };
const PERM_BITS: Record<Perm, number> = { r: 4, w: 2, rw: 6 };

export function inGroup(p: Principal, gid: number): boolean {
  return p.gid === gid || p.groups.includes(gid);
}

export const allGroups = (p: Principal): number[] => [p.gid, ...p.groups.filter((g) => g !== p.gid)];

export function isOwner(p: Principal, x: Guarded): boolean {
  return x.owner !== null && p.agentId === x.owner;
}

/** Steps 1-3: owner, then any group, then other. */
export function digitFor(p: Principal, x: Guarded): number {
  if (isOwner(p, x)) return Number(x.mode[0]);
  if (inGroup(p, x.gid)) return Number(x.mode[1]);
  return Number(x.mode[2]);
}

/** Step 4: the ACL entries naming one of a non-owner's groups. */
export function matchingAcl(p: Principal, x: Guarded): AclEntry[] {
  if (isOwner(p, x)) return [];
  return (x.acl ?? []).filter((e) => inGroup(p, e.gid));
}

export function matchingUsers(p: Principal, x: Guarded): UserAclEntry[] {
  if (isOwner(p, x) || !p.userId) return [];
  return (x.users ?? []).filter((e) => e.userId === p.userId);
}

export function modeAllows(p: Principal, x: Guarded, op: Op): boolean {
  const bits = [...matchingAcl(p, x), ...matchingUsers(p, x)].reduce((acc, e) => acc | PERM_BITS[e.perm], digitFor(p, x));
  return (bits & BIT[op]) !== 0;
}

/** Step 5: the first ceiling that forbids one of `p`'s groups from `gid`. */
export function ceilingFor(p: Principal, gid: number, ceilings: readonly Ceiling[]): Ceiling | undefined {
  return ceilings.find((c) => inGroup(p, c.gid) && c.never.includes(gid));
}

export interface CheckStep {
  step: "owner" | "group" | "other" | "acl" | "user_acl" | "ceiling";
  detail: string;
}

export interface CheckResult {
  allowed: boolean;
  /** The read/write bits `p` ends up with (0 when a ceiling refused). */
  bits: number;
  /** Content-free, auditable summary, e.g. `mode:660+acl:<gid>:rw` or `ceiling:<gid>-><gid>`. */
  reason: string;
  /** Every step that applied, in order, for operators ("explain"). */
  steps: CheckStep[];
}

const bitsText = (bits: number) => (bits & 4 ? "r" : "-") + (bits & 2 ? "w" : "-");

/** The full deterministic check, with the trace an operator needs to see why. */
export function check(p: Principal, x: Guarded, op: Op, ceilings: readonly Ceiling[] = []): CheckResult {
  const steps: CheckStep[] = [];
  const digit = digitFor(p, x);
  if (isOwner(p, x)) steps.push({ step: "owner", detail: `owner digit ${x.mode[0]} (${bitsText(digit)})` });
  else if (inGroup(p, x.gid)) steps.push({ step: "group", detail: `member of gid ${x.gid}: group digit ${x.mode[1]} (${bitsText(digit)})` });
  else steps.push({ step: "other", detail: `not owner, not in gid ${x.gid}: other digit ${x.mode[2]} (${bitsText(digit)})` });

  let bits = digit;
  const acl = matchingAcl(p, x);
  for (const e of acl) {
    bits |= PERM_BITS[e.perm];
    steps.push({ step: "acl", detail: `acl ${e.gid}:${e.perm} adds ${bitsText(PERM_BITS[e.perm])}` });
  }
  const users = matchingUsers(p, x);
  for (const e of users) {
    bits |= PERM_BITS[e.perm];
    steps.push({ step: "user_acl", detail: `user acl ${e.userId}:${e.perm} adds ${bitsText(PERM_BITS[e.perm])}` });
  }
  const reason = `mode:${x.mode}${acl.map((e) => `+acl:${e.gid}:${e.perm}`).join("")}${users.map((e) => `+user:${e.perm}`).join("")}`;

  for (const gid of [...new Set([x.gid, ...(x.ceilingGids ?? [])])]) {
    const ceiling = ceilingFor(p, gid, ceilings);
    if (ceiling) {
      steps.push({ step: "ceiling", detail: `gid ${ceiling.gid} may never touch gid ${gid}: refused` });
      return { allowed: false, bits: 0, reason: `ceiling:${ceiling.gid}->${gid}`, steps };
    }
  }
  return { allowed: (bits & BIT[op]) !== 0, bits, reason, steps };
}
