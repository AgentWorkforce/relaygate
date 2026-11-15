/** The deterministic check from docs/contract.md, "The check". */

export type Op = "r" | "w";

export interface Principal {
  agentId: string;
  /** Primary group, set at registration. */
  gid: number;
  /** Supplementary groups, from the operator's policy. */
  groups: readonly number[];
}

export interface Guarded {
  /** agent_id of the owner, or null when the resource comes from a policy default or override. */
  owner: string | null;
  gid: number;
  /** Three octal digits: owner, group, other. */
  mode: string;
}

const BIT: Record<Op, number> = { r: 4, w: 2 };

export function inGroup(p: Principal, gid: number): boolean {
  return p.gid === gid || p.groups.includes(gid);
}

export function digitFor(p: Principal, x: Guarded): number {
  if (x.owner !== null && p.agentId === x.owner) return Number(x.mode[0]);
  if (inGroup(p, x.gid)) return Number(x.mode[1]);
  return Number(x.mode[2]);
}

export function modeAllows(p: Principal, x: Guarded, op: Op): boolean {
  return (digitFor(p, x) & BIT[op]) !== 0;
}
