import type { Principal } from "./mode.js";
import type { Policy } from "./policy.js";
import { sha256, type Agent, type Store } from "./store.js";
import { isHostedClient, type HostedClient } from "./hosted-clients.js";
export { HOSTED_CLIENTS, type HostedClient } from "./hosted-clients.js";

/**
 * Principals that hold only relay-control credentials (docs/contract.md, "Control principals"): the desktop app
 * uploading with its device token (`sh_at_`), and dashboard reads with Control-issued read tokens (`rth_at_read_`,
 * `rth_st_read_`). relaygate learns who they are, then maps them to groups by the policy's `controlPrincipals` rules.
 *
 * - Device tokens are introspected with relay-control (POST /internal/v1/auth/introspect).
 * - Read tokens can't be introspected by anyone but session-read-api, so relaygate learns them as they are minted:
 *   relay-control mints them through relaygate (its Sessions read URL points here), and relaygate records the
 *   token's hash with the identity the mint named.
 */

export interface ControlConfig {
  /** relay-control's POST /internal/v1/auth/introspect URL. */
  introspectUrl: string;
  /** RELAYCONTROL_INTROSPECT_SECRET. */
  introspectSecret: string;
  /** The audience device tokens are introspected for (the Sessions ingest origin Control accepts). */
  audience: string;
  fetch?: typeof fetch;
  /** How long a positive introspection is reused (capped at the token's expiry). Default 15 s. */
  cacheMs?: number;
}

export type ControlRole = "owner" | "admin" | "member";

export type ControlKind = "device" | "read" | "launch" | "hosted";

export interface ControlIdentity {
  kind: ControlKind;
  /** Launch and hosted credentials only: the one agent name it may enrol. */
  agentName?: string;
  /** Hosted credentials only: which hosted MCP client the agent belongs to. */
  client?: HostedClient;
  userId: string;
  email?: string;
  orgId: string;
  workspaceId?: string;
  /** The live org role. Device tokens always have it; read tokens only if Control sent it with the mint. */
  role?: ControlRole;
  scopes: string[];
  /** Expiry, ms since the epoch. */
  expiresAt?: number;
  /** Read tokens only: how the reader authenticated to relay-control, as relay-control set it on the mint. */
  readerKind?: ReaderKind;
}

/** browser: a cookie-authenticated dashboard session; device: a desktop or CLI bearer; mcp: an agent-behalf read. */
export const READER_KINDS = ["browser", "device", "mcp"] as const;
export type ReaderKind = (typeof READER_KINDS)[number];
const isReaderKind = (v: unknown): v is ReaderKind => typeof v === "string" && (READER_KINDS as readonly string[]).includes(v);

/**
 * The reader_kind relay-control put on a mint request, and the request with it removed (the read API doesn't take it).
 * Unparseable bodies pass through untouched.
 */
export function takeReaderKind(text: string): { readerKind: ReaderKind | undefined; body: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { readerKind: undefined, body: text };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !("reader_kind" in parsed)) return { readerKind: undefined, body: text };
  const { reader_kind, ...rest } = parsed as Record<string, unknown>;
  return { readerKind: isReaderKind(reader_kind) ? reader_kind : undefined, body: JSON.stringify(rest) };
}

export class ControlUnavailable extends Error {}

const ROLES = new Set(["owner", "admin", "member"]);
/** Device-token identities kept in memory at most. */
const CACHE_MAX = 10_000;
/** Longest relaygate remembers a minted read token (service tokens can live 90 days). */
const MAX_READ_TOKEN_MS = 90 * 24 * 3600 * 1000;

/** Which credential a bearer token is, by its prefix. */
export function controlTokenKind(token: string): ControlKind | undefined {
  if (token.startsWith("sh_at_")) return "device";
  if (token.startsWith("sh_lt_")) return "launch";
  if (token.startsWith("sh_ht_")) return "hosted";
  if (token.startsWith("rth_at_read_") || token.startsWith("rth_st_read_")) return "read";
  return undefined;
}

export class ControlAuth {
  private cache = new Map<string, { identity: ControlIdentity; until: number }>();
  private doFetch: typeof fetch;

  constructor(
    readonly cfg: ControlConfig,
    private store: Store,
    private now: () => number = Date.now,
  ) {
    this.doFetch = cfg.fetch ?? fetch;
  }

  /** Who holds this token, or undefined if it isn't valid. Throws ControlUnavailable when Control can't answer. */
  async identify(token: string): Promise<ControlIdentity | undefined> {
    const kind = controlTokenKind(token);
    if (kind === "read") return this.readToken(token);
    if (kind === "device" || kind === "launch" || kind === "hosted") return this.introspect(token, kind);
    return undefined;
  }

  private readToken(token: string): ControlIdentity | undefined {
    const row = this.store.controlReadToken(sha256(token), this.now());
    if (!row) return undefined;
    // The mint rarely carries an email; fall back to the one relay-control last reported for this user.
    const email = row.email ?? this.store.controlEmail(row.userId);
    const readerKind = isReaderKind(row.readerKind) ? row.readerKind : undefined;
    return { kind: "read", userId: row.userId, email, orgId: row.orgId, workspaceId: row.workspaceId ?? undefined, role: row.role ?? undefined, scopes: ["rth:read"], expiresAt: row.expiresAt ?? undefined, readerKind };
  }

  private async introspect(token: string, kind: "device" | "launch" | "hosted"): Promise<ControlIdentity | undefined> {
    const key = sha256(token);
    const hit = kind === "device" ? this.cache.get(key) : undefined;
    if (hit && hit.until > this.now()) return hit.identity;
    let res: Response;
    try {
      res = await this.doFetch(this.cfg.introspectUrl, {
        method: "POST",
        headers: { authorization: `Bearer ${this.cfg.introspectSecret}`, "content-type": "application/json" },
        body: JSON.stringify({ token, aud: this.cfg.audience }),
        signal: AbortSignal.timeout(5000),
      });
    } catch (error) {
      throw new ControlUnavailable(`introspection failed: ${(error as Error).name}`);
    }
    // Control answers 200 for every well-formed, authenticated request; anything else means it couldn't decide.
    if (res.status !== 200) throw new ControlUnavailable(`introspection answered ${res.status}`);
    let body: Record<string, unknown> | null;
    try {
      body = (await res.json()) as Record<string, unknown> | null;
    } catch {
      // A 200 that can't be read is Control failing, not the token being bad.
      throw new ControlUnavailable("introspection answer could not be read");
    }
    if (!body || body.active !== true) return undefined;
    // A device token is a person on their desktop; a launch credential is one agent a person launched; a hosted
    // credential is one hosted MCP participant a person's connector (ChatGPT, Cursor cloud agents, ...) joins with.
    const expected = kind === "device" ? "desktop-user" : kind === "launch" ? "relay_launch" : "relay_hosted";
    if (body.principal_type !== expected || typeof body.sub !== "string" || typeof body.org !== "string") return undefined;
    if (kind !== "device" && (typeof body.agent_name !== "string" || !body.agent_name)) return undefined;
    // An unknown client is refused, never treated as a generic one: it would match rules meant for another client.
    if (kind === "hosted" && !isHostedClient(body.client)) return undefined;
    const identity: ControlIdentity = {
      kind,
      ...(kind !== "device" ? { agentName: body.agent_name as string } : {}),
      ...(kind === "hosted" ? { client: body.client as HostedClient } : {}),
      userId: body.sub,
      email: typeof body.email === "string" ? body.email : undefined,
      orgId: body.org,
      workspaceId: typeof body.workspace === "string" ? body.workspace : undefined,
      role: typeof body.role === "string" && ROLES.has(body.role) ? (body.role as ControlRole) : undefined,
      scopes: Array.isArray(body.scopes) ? body.scopes.filter((s): s is string => typeof s === "string") : [],
      expiresAt: typeof body.exp === "number" ? body.exp * 1000 : undefined,
    };
    if (identity.email) this.store.rememberControlEmail(identity.userId, identity.email);
    // Launch and hosted credentials are single-use (relay-control burns them): never answered from cache.
    if (kind === "device") {
      const until = Math.min(this.now() + (this.cfg.cacheMs ?? 15_000), identity.expiresAt ?? Infinity);
      this.remember(key, { identity, until });
    }
    return identity;
  }

  /** Bounded: expired entries go first, then the oldest, so rotated tokens never pile up. */
  private remember(key: string, entry: { identity: ControlIdentity; until: number }): void {
    const now = this.now();
    if (this.cache.size >= CACHE_MAX) {
      for (const [k, v] of this.cache) if (v.until <= now) this.cache.delete(k);
      while (this.cache.size >= CACHE_MAX) this.cache.delete(this.cache.keys().next().value!);
    }
    this.cache.set(key, entry);
  }

  /** Records a read token relay-control just minted through relaygate (its hash, never the token). */
  recordMint(body: unknown, readerKind?: ReaderKind, now = this.now()): boolean {
    const b = body as Record<string, unknown> | null;
    const token = typeof b?.accessToken === "string" ? b.accessToken : typeof b?.token === "string" ? b.token : undefined;
    if (!token || controlTokenKind(token) !== "read" || typeof b?.userId !== "string" || typeof b?.orgId !== "string") return false;
    // ISO string or epoch milliseconds; without one, the token is kept until relaygate's own cap (below).
    const raw = b.accessTokenExpiresAt ?? b.expiresAt;
    const parsed = typeof raw === "number" ? raw : typeof raw === "string" ? Date.parse(raw) : NaN;
    const exp = Number.isFinite(parsed) ? Math.min(parsed, now + MAX_READ_TOKEN_MS) : now + MAX_READ_TOKEN_MS;
    const role = typeof b.role === "string" && ROLES.has(b.role) ? b.role : null;
    this.store.putControlReadToken({
      hash: sha256(token),
      refreshHash: typeof b.refreshToken === "string" && b.refreshToken.startsWith("rth_rt_read_") ? sha256(b.refreshToken) : null,
      sessionId: typeof b.sessionId === "string" ? b.sessionId : null,
      userId: b.userId,
      orgId: b.orgId,
      workspaceId: typeof b.workspaceId === "string" ? b.workspaceId : null,
      role: role as ControlRole | null,
      email: typeof b.email === "string" ? b.email : null,
      readerKind: readerKind ?? null,
      expiresAt: exp,
    });
    this.store.pruneControlReadTokens(now);
    return true;
  }

  /** Mirrors a successful holder revoke so a locally handled management call cannot reuse the old access token. */
  recordClientRevoke(body: unknown): boolean {
    const token = (body as Record<string, unknown> | null)?.token;
    return typeof token === "string" && this.store.revokeControlReadToken(token) > 0;
  }

  /** Mirrors relay-control's successful internal revoke by read-session identity. */
  recordInternalRevoke(body: unknown): boolean {
    const b = body as Record<string, unknown> | null;
    if (typeof b?.orgId !== "string") return false;
    const filter = {
      orgId: b.orgId,
      ...(typeof b.id === "string" ? { sessionId: b.id } : typeof b.sessionId === "string" ? { sessionId: b.sessionId } : {}),
      ...(typeof b.userId === "string" ? { userId: b.userId } : {}),
      ...(typeof b.workspaceId === "string" ? { workspaceId: b.workspaceId } : {}),
    };
    return this.store.revokeControlReadSessions(filter) > 0;
  }
}

export type ControlRule = Policy["controlPrincipals"][number];

/** The first policy rule that matches the identity; undefined means the caller is refused. */
export function matchControlRule(identity: ControlIdentity, policy: Policy, as: "person" | "agent"): ControlRule | undefined {
  return policy.controlPrincipals.find((rule) => {
    const m = rule.match;
    if (m.as && !m.as.includes(as)) return false;
    // Fails closed: a hosted credential matches only a rule that names the hosted kind, so a catch-all rule (no
    // `kinds`) written for people and their desktops never takes a hosted MCP participant into its group.
    if (identity.kind === "hosted" && !m.kinds?.includes("hosted")) return false;
    if (m.kinds && !m.kinds.includes(identity.kind)) return false;
    // Only a hosted credential carries a client; any other credential matches no rule that sets `clients`.
    if (m.clients && (!identity.client || !m.clients.includes(identity.client))) return false;
    // Fails closed: a read token minted without a reader_kind (an older relay-control) matches no readerKinds rule.
    if (m.readerKinds && (!identity.readerKind || !m.readerKinds.includes(identity.readerKind))) return false;
    if (m.orgIds && !m.orgIds.includes(identity.orgId)) return false;
    if (m.workspaceIds && (!identity.workspaceId || !m.workspaceIds.includes(identity.workspaceId))) return false;
    if (m.roles && (!identity.role || !m.roles.includes(identity.role))) return false;
    if (m.userIds && !m.userIds.includes(identity.userId)) return false;
    if (m.emails && (!identity.email || !m.emails.map((e) => e.toLowerCase()).includes(identity.email.toLowerCase()))) return false;
    return true;
  });
}

/** The relaygate agent standing for a Control user (audited, owns what it uploads), and its principal now. */
export function controlPrincipal(store: Store, identity: ControlIdentity, rule: ControlRule): { agent: Agent; principal: Principal } {
  const agent = store.ensureControlAgent(identity.userId, rule.gid);
  return { agent, principal: { agentId: agent.id, userId: identity.userId, gid: rule.gid, groups: rule.groups } };
}
