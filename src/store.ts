import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { AclEntry } from "./mode.js";

export const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

export function sameHash(a: string, b: string): boolean {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === y.length && timingSafeEqual(x, y);
}

/** AES-256-GCM for upstream credentials at rest. The key comes from RELAYGATE_SECRET, never the database. */
export class SecretBox {
  private key: Buffer;
  constructor(secret: string) {
    this.key = createHash("sha256").update(secret).digest();
  }
  seal(plain: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.key, iv);
    const body = Buffer.concat([c.update(plain, "utf8"), c.final()]);
    return [iv, c.getAuthTag(), body].map((b) => b.toString("base64url")).join(".");
  }
  open(sealed: string): string {
    const [iv, tag, body] = sealed.split(".").map((p) => Buffer.from(p, "base64url"));
    const d = createDecipheriv("aes-256-gcm", this.key, iv!);
    d.setAuthTag(tag!);
    return Buffer.concat([d.update(body!), d.final()]).toString("utf8");
  }
}

export interface NodeTokenRow {
  agentId: string;
  /** Hash of the rg_ token that minted it; the node token dies with that token. */
  agentTokenHash: string;
  nodeId: string;
  upstreamSealed: string;
}

export interface Agent {
  id: string;
  name: string;
  gid: number;
  /** The enrollment key the agent registered with; its supplementary groups come from the current policy. */
  keyId: string;
  recoveryHash: string | null;
  /** Enrolled with a guest key. Kept on the agent so removing the key from the policy can't make a guest a member. */
  guest: boolean;
  /** Supplementary groups for agents enrolled without a policy key (a person's desktop, via controlPrincipals). */
  groups: number[] | null;
}

export interface StreamRow {
  id: string;
  owner: string;
  gid: number;
  mode: string;
  classify: boolean;
  acl: AclEntry[];
}

export interface AuditEntry {
  agentId: string | null;
  action: string;
  op: string | null;
  resourceKind: string | null;
  resourceId: string | null;
  decision: "allow" | "deny" | "unavailable";
  stage: "auth" | "mode" | "classifier" | "registration" | null;
  reason: string | null;
  /** The policy the decision was evaluated under; defaults to the one in force now (for synchronous decisions). */
  policyVersion?: string;
}

export class Store {
  private db: DatabaseSync;
  /** The agent columns this database has (all of them, once migrated). */
  private agentCols = "id, name, gid, key_id, recovery_hash, guest, groups";

  /** `readOnly` opens an existing database without creating or migrating anything (for the explain CLI). */
  constructor(path: string, opts: { readOnly?: boolean } = {}) {
    this.db = new DatabaseSync(path, { readOnly: opts.readOnly ?? false });
    if (opts.readOnly) {
      // A read-only database isn't migrated: read the agent columns it has (an older one lacks guest/groups).
      const cols = new Set(this.db.prepare("PRAGMA table_info(agents)").all().map((c) => String(c.name)));
      this.agentCols = `id, name, gid, key_id, recovery_hash, ${cols.has("guest") ? "guest" : "0 AS guest"}, ${cols.has("groups") ? "groups" : "NULL AS groups"}`;
      return;
    }
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        gid INTEGER NOT NULL,
        key_id TEXT NOT NULL,
        recovery_hash TEXT,
        guest INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS tokens (
        hash TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id),
        revoked INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS streams (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL REFERENCES agents(id),
        gid INTEGER NOT NULL,
        mode TEXT NOT NULL,
        classify INTEGER NOT NULL,
        acl TEXT NOT NULL DEFAULT '[]',
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS upstream_agents (
        agent_id TEXT PRIMARY KEY REFERENCES agents(id),
        upstream_id TEXT NOT NULL,
        token_sealed TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS node_tokens (
        hash TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL REFERENCES agents(id),
        agent_token_hash TEXT NOT NULL,
        node_id TEXT NOT NULL,
        upstream_sealed TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS node_tokens_by_agent_token ON node_tokens (agent_token_hash);
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL REFERENCES agents(id),
        gid INTEGER NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS control_read_tokens (
        hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        workspace_id TEXT,
        role TEXT,
        email TEXT,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS policy_cache (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL,
        body TEXT NOT NULL,
        signature TEXT NOT NULL,
        fetched_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS control_users (
        user_id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,
        agent_id TEXT,
        action TEXT NOT NULL,
        op TEXT,
        resource_kind TEXT,
        resource_id TEXT,
        decision TEXT NOT NULL,
        stage TEXT,
        reason TEXT
      );
    `);
    // Databases from build 1 predate these columns.
    this.addColumn("agents", "guest", "INTEGER NOT NULL DEFAULT 0");
    this.addColumn("streams", "acl", "TEXT NOT NULL DEFAULT '[]'");
    this.addColumn("audit", "policy_version", "TEXT");
    this.addColumn("control_read_tokens", "email", "TEXT");
    this.addColumn("agents", "groups", "TEXT");
    this.addColumn("tokens", "expires_at", "INTEGER");
    this.addColumn("agents", "last_seen_at", "INTEGER");
    this.addColumn("tokens", "binding", "TEXT");
    this.addColumn("control_read_tokens", "reader_kind", "TEXT");
  }

  private addColumn(table: string, column: string, decl: string): void {
    const cols = this.db.prepare(`PRAGMA table_info(${table})`).all().map((c) => String(c.name));
    if (!cols.includes(column)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  }

  /** The last policy version applied from relay-control, exactly as it was served (re-verified on startup). */
  cachePolicy(row: { version: number; body: string; signature: string; fetchedAt: string }): void {
    this.db
      .prepare(
        `INSERT INTO policy_cache (id, version, body, signature, fetched_at) VALUES (1, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET version = excluded.version, body = excluded.body, signature = excluded.signature, fetched_at = excluded.fetched_at`,
      )
      .run(row.version, row.body, row.signature, row.fetchedAt);
  }

  cachedPolicy(): { version: number; body: string; signature: string; fetchedAt: string } | undefined {
    const row = this.db.prepare("SELECT version, body, signature, fetched_at FROM policy_cache WHERE id = 1").get();
    return row ? { version: Number(row.version), body: String(row.body), signature: String(row.signature), fetchedAt: String(row.fetched_at) } : undefined;
  }

  ping(): boolean {
    return this.db.prepare("SELECT 1 AS ok").get()?.ok === 1;
  }

  agentByName(name: string): Agent | undefined {
    const row = this.db.prepare(`SELECT ${this.agentCols} FROM agents WHERE name = ?`).get(name);
    return row ? toAgent(row) : undefined;
  }

  createAgent(name: string, gid: number, keyId: string, recovery: string | undefined, guest = false, groups: number[] | null = null): Agent {
    const agent: Agent = {
      id: `ag_${randomUUID()}`,
      name,
      gid,
      keyId,
      recoveryHash: recovery ? sha256(recovery) : null,
      guest,
      groups,
    };
    this.db
      .prepare("INSERT INTO agents (id, name, gid, key_id, recovery_hash, guest, groups, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(agent.id, agent.name, agent.gid, agent.keyId, agent.recoveryHash, agent.guest ? 1 : 0, groups ? JSON.stringify(groups) : null, now());
    return agent;
  }

  /** Revokes every token the agent holds and returns the hashes that were revoked. */
  /** Revokes an agent's tokens issued under one binding (one computer), leaving its other computers' tokens. */
  revokeBoundTokens(agentId: string, binding: string | null): string[] {
    const where = binding === null ? "binding IS NULL" : "binding = ?";
    const args = binding === null ? [agentId] : [agentId, binding];
    const rows = this.db.prepare(`SELECT hash FROM tokens WHERE agent_id = ? AND revoked = 0 AND ${where}`).all(...args);
    this.db.prepare(`UPDATE tokens SET revoked = 1 WHERE agent_id = ? AND ${where}`).run(...args);
    return rows.map((r) => String(r.hash));
  }

  revokeTokens(agentId: string): string[] {
    const rows = this.db.prepare("SELECT hash FROM tokens WHERE agent_id = ? AND revoked = 0").all(agentId);
    this.db.prepare("UPDATE tokens SET revoked = 1 WHERE agent_id = ?").run(agentId);
    return rows.map((r) => String(r.hash));
  }

  revokeTokenHash(hash: string): void {
    this.db.prepare("UPDATE tokens SET revoked = 1 WHERE hash = ?").run(hash);
  }

  /** Revokes every token issued to guest agents enrolled with the key; returns the revoked hashes. */
  revokeGuestKeyTokens(keyId: string): string[] {
    const agents = "SELECT id FROM agents WHERE key_id = ? AND guest = 1";
    const rows = this.db.prepare(`SELECT hash FROM tokens WHERE revoked = 0 AND agent_id IN (${agents})`).all(keyId);
    this.db.prepare(`UPDATE tokens SET revoked = 1 WHERE revoked = 0 AND agent_id IN (${agents})`).run(keyId);
    return rows.map((r) => String(r.hash));
  }

  /** Records that agents enrolled with this key are guests, so removing the key from the policy can't un-guest them. */
  markKeyGuest(keyId: string): void {
    this.db.prepare("UPDATE agents SET guest = 1 WHERE key_id = ? AND guest = 0").run(keyId);
  }

  /** Enrollment key ids that guest agents registered with. */
  guestKeyIds(): string[] {
    return this.db.prepare("SELECT DISTINCT key_id FROM agents WHERE guest = 1").all().map((r) => String(r.key_id));
  }

  /** Re-associates an agent with the enrollment key that just recovered it (key rotation). */
  setAgentKey(agentId: string, keyId: string, guest: boolean): void {
    this.db.prepare("UPDATE agents SET key_id = ?, guest = MAX(guest, ?) WHERE id = ?").run(keyId, guest ? 1 : 0, agentId);
  }

  /** `binding` ties the token to one computer's recovery proof, so re-registering there rotates only its own token. */
  issueToken(agentId: string, expiresAt?: number, binding?: string): string {
    const token = `rg_${randomBytes(32).toString("base64url")}`;
    this.db.prepare("INSERT INTO tokens (hash, agent_id, created_at, expires_at, binding) VALUES (?, ?, ?, ?, ?)").run(sha256(token), agentId, now(), expiresAt ?? null, binding ?? null);
    this.touchAgent(agentId, this.clock(), true);
    return token;
  }

  /** Milliseconds since the epoch; the app sets its own clock here. */
  clock: () => number = Date.now;
  private seen = new Map<string, number>();

  /** Records that an agent was just active: at most one write a minute per agent unless forced. */
  touchAgent(agentId: string, at: number, force = false): void {
    const last = this.seen.get(agentId);
    if (!force && last !== undefined && at - last < 60_000) return;
    if (this.seen.size > 50_000) this.seen.clear();
    this.seen.set(agentId, at);
    this.db.prepare("UPDATE agents SET last_seen_at = ? WHERE id = ?").run(at, agentId);
  }

  /** Per enrollment key id: its agents, their unexpired unrevoked tokens, and when one of them was last active. */
  keyUsage(at: number): Map<string, { agents: number; activeTokens: number; lastUsedAt: number | null }> {
    const rows = this.db
      .prepare(
        `SELECT a.key_id AS key_id, COUNT(DISTINCT a.id) AS agents, MAX(a.last_seen_at) AS last_seen,
                COUNT(t.hash) AS active
           FROM agents a
           LEFT JOIN tokens t ON t.agent_id = a.id AND t.revoked = 0 AND (t.expires_at IS NULL OR t.expires_at > ?)
          GROUP BY a.key_id`,
      )
      .all(at);
    return new Map(
      rows.map((r) => [String(r.key_id), { agents: Number(r.agents), activeTokens: Number(r.active), lastUsedAt: r.last_seen === null ? null : Number(r.last_seen) }]),
    );
  }

  /** A desktop-enrolled agent's group follows its person's current controlPrincipals rule (set on each registration). */
  setAgentGroups(agentId: string, gid: number, groups: number[]): void {
    this.db.prepare("UPDATE agents SET gid = ?, groups = ? WHERE id = ?").run(gid, JSON.stringify(groups), agentId);
  }

  /** Forgets the upstream credential of a removed agent (the next use registers it upstream afresh). */
  deleteUpstreamAgent(agentId: string): void {
    this.db.prepare("DELETE FROM upstream_agents WHERE agent_id = ?").run(agentId);
  }

  agentForToken(token: string): Agent | undefined {
    return this.agentForTokenHash(sha256(token));
  }

  agentForTokenHash(hash: string): Agent | undefined {
    const row = this.db
      .prepare(
        "SELECT a.id, a.name, a.gid, a.key_id, a.recovery_hash, a.guest, a.groups FROM tokens t JOIN agents a ON a.id = t.agent_id WHERE t.hash = ? AND t.revoked = 0 AND (t.expires_at IS NULL OR t.expires_at > ?)",
      )
      .get(hash, Date.now());
    return row ? toAgent(row) : undefined;
  }

  session(id: string): { id: string; owner: string; gid: number } | undefined {
    const row = this.db.prepare("SELECT id, owner, gid FROM sessions WHERE id = ?").get(id);
    return row ? { id: String(row.id), owner: String(row.owner), gid: Number(row.gid) } : undefined;
  }

  /**
   * Claims every id for `owner` in one transaction, or none: if any is already owned by someone else, nothing is
   * written and the ids that were taken are returned.
   */
  claimSessions(ids: string[], owner: string, gid: number): { claimed: boolean; taken: string[] } {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const taken = ids.filter((id) => {
        const row = this.session(id);
        return row !== undefined && row.owner !== owner;
      });
      if (taken.length > 0) {
        this.db.exec("ROLLBACK");
        return { claimed: false, taken };
      }
      const insert = this.db.prepare("INSERT OR IGNORE INTO sessions (id, owner, gid, created_at) VALUES (?, ?, ?, ?)");
      for (const id of ids) insert.run(id, owner, gid, now());
      this.db.exec("COMMIT");
      return { claimed: true, taken: [] };
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  /** The relaygate agent standing for a relay-control user (`ctl:<userId>`), created on first sight. */
  ensureControlAgent(userId: string, gid: number): Agent {
    const name = `ctl:${userId}`;
    const existing = this.agentByName(name);
    if (existing) {
      // Only an agent relaygate itself created for this Control user stands for it; a registered agent never does.
      if (existing.keyId !== "control") throw new Error(`agent ${name} exists and is not a Control identity`);
      if (existing.gid !== gid) {
        this.db.prepare("UPDATE agents SET gid = ? WHERE id = ?").run(gid, existing.id);
        existing.gid = gid;
      }
      return existing;
    }
    return this.createAgent(name, gid, "control", undefined);
  }

  putControlReadToken(row: { hash: string; userId: string; orgId: string; workspaceId: string | null; role: string | null; email: string | null; readerKind: string | null; expiresAt: number }): void {
    this.db
      .prepare(
        `INSERT INTO control_read_tokens (hash, user_id, org_id, workspace_id, role, email, reader_kind, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(hash) DO UPDATE SET user_id = excluded.user_id, org_id = excluded.org_id, workspace_id = excluded.workspace_id, role = excluded.role, email = excluded.email, reader_kind = excluded.reader_kind, expires_at = excluded.expires_at`,
      )
      .run(row.hash, row.userId, row.orgId, row.workspaceId, row.role, row.email, row.readerKind, row.expiresAt);
  }

  /** A Control user's email, as relay-control last reported it (introspection, or a mint that carried it). */
  rememberControlEmail(userId: string, email: string): void {
    this.db
      .prepare("INSERT INTO control_users (user_id, email, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET email = excluded.email, updated_at = excluded.updated_at")
      .run(userId, email, now());
  }

  controlEmail(userId: string): string | undefined {
    const row = this.db.prepare("SELECT email FROM control_users WHERE user_id = ?").get(userId);
    return row ? String(row.email) : undefined;
  }

  controlReadToken(hash: string, now: number): { userId: string; orgId: string; workspaceId: string | null; role: "owner" | "admin" | "member" | null; email: string | null; readerKind: string | null; expiresAt: number } | undefined {
    const row = this.db.prepare("SELECT user_id, org_id, workspace_id, role, email, reader_kind, expires_at FROM control_read_tokens WHERE hash = ? AND expires_at > ?").get(hash, now);
    return row
      ? {
          userId: String(row.user_id),
          orgId: String(row.org_id),
          workspaceId: row.workspace_id === null ? null : String(row.workspace_id),
          role: row.role === null ? null : (String(row.role) as "owner"),
          email: row.email === null ? null : String(row.email),
          readerKind: row.reader_kind === null || row.reader_kind === undefined ? null : String(row.reader_kind),
          expiresAt: Number(row.expires_at),
        }
      : undefined;
  }

  pruneControlReadTokens(now: number): void {
    this.db.prepare("DELETE FROM control_read_tokens WHERE expires_at <= ?").run(now);
  }

  upstreamAgent(agentId: string): { upstreamId: string; tokenSealed: string } | undefined {
    const row = this.db.prepare("SELECT upstream_id, token_sealed FROM upstream_agents WHERE agent_id = ?").get(agentId);
    return row ? { upstreamId: String(row.upstream_id), tokenSealed: String(row.token_sealed) } : undefined;
  }

  putUpstreamAgent(agentId: string, upstreamId: string, tokenSealed: string): void {
    this.db
      .prepare(
        `INSERT INTO upstream_agents (agent_id, upstream_id, token_sealed, updated_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(agent_id) DO UPDATE SET upstream_id = excluded.upstream_id, token_sealed = excluded.token_sealed, updated_at = excluded.updated_at`,
      )
      .run(agentId, upstreamId, tokenSealed, now());
  }

  /**
   * Issues an rgn_ node token bound to the rg_ token that asked for it, and prunes: rows bound to the agent's
   * revoked rg_ tokens go, and only the newest few per rg_ token are kept (a token is used once, to open a socket).
   */
  issueNodeToken(row: NodeTokenRow): string {
    const token = `rgn_${randomBytes(32).toString("base64url")}`;
    this.db
      .prepare("INSERT INTO node_tokens (hash, agent_id, agent_token_hash, node_id, upstream_sealed, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(sha256(token), row.agentId, row.agentTokenHash, row.nodeId, row.upstreamSealed, now());
    this.db
      .prepare("DELETE FROM node_tokens WHERE agent_id = ? AND agent_token_hash IN (SELECT hash FROM tokens WHERE agent_id = ? AND revoked = 1)")
      .run(row.agentId, row.agentId);
    this.db
      .prepare(
        `DELETE FROM node_tokens WHERE agent_token_hash = ? AND rowid NOT IN
           (SELECT rowid FROM node_tokens WHERE agent_token_hash = ? ORDER BY rowid DESC LIMIT ${NODE_TOKENS_KEPT})`,
      )
      .run(row.agentTokenHash, row.agentTokenHash);
    return token;
  }

  nodeToken(token: string): NodeTokenRow | undefined {
    const row = this.db
      .prepare("SELECT agent_id, agent_token_hash, node_id, upstream_sealed FROM node_tokens WHERE hash = ?")
      .get(sha256(token));
    return row
      ? { agentId: String(row.agent_id), agentTokenHash: String(row.agent_token_hash), nodeId: String(row.node_id), upstreamSealed: String(row.upstream_sealed) }
      : undefined;
  }

  stream(id: string): StreamRow | undefined {
    const row = this.db.prepare("SELECT id, owner, gid, mode, classify, acl FROM streams WHERE id = ?").get(id);
    if (!row) return undefined;
    return {
      id: String(row.id),
      owner: String(row.owner),
      gid: Number(row.gid),
      mode: String(row.mode),
      classify: Number(row.classify) === 1,
      acl: JSON.parse(String(row.acl)) as AclEntry[],
    };
  }

  putStream(s: StreamRow): void {
    this.db
      .prepare(
        `INSERT INTO streams (id, owner, gid, mode, classify, acl, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET gid = excluded.gid, mode = excluded.mode, classify = excluded.classify, acl = excluded.acl, updated_at = excluded.updated_at`,
      )
      .run(s.id, s.owner, s.gid, s.mode, s.classify ? 1 : 0, JSON.stringify(s.acl), now());
  }

  /** Version of the policy in force, recorded on every audit row (set by the app). */
  policyVersion: () => string | null = () => null;

  audit(e: AuditEntry): void {
    this.db
      .prepare(
        "INSERT INTO audit (at, agent_id, action, op, resource_kind, resource_id, decision, stage, reason, policy_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(now(), e.agentId, e.action, e.op, e.resourceKind, e.resourceId, e.decision, e.stage, e.reason, e.policyVersion ?? this.policyVersion());
  }

  /** Audit rows after `after` (a seq), oldest first, with the agent's name. Never contains message content. */
  auditSince(after: number, limit: number, agentName?: string): Array<Record<string, unknown>> {
    const where = agentName ? "AND g.name = ?" : "";
    const params: Array<string | number> = [after, ...(agentName ? [agentName] : []), limit];
    return this.db
      .prepare(`SELECT a.*, g.name AS agent_name FROM audit a LEFT JOIN agents g ON g.id = a.agent_id WHERE a.seq > ? ${where} ORDER BY a.seq ASC LIMIT ?`)
      .all(...params) as Array<Record<string, unknown>>;
  }

  recentAudit(limit = 100): Array<Record<string, unknown>> {
    return this.db.prepare("SELECT * FROM audit ORDER BY seq DESC LIMIT ?").all(limit) as Array<Record<string, unknown>>;
  }

  close(): void {
    this.db.close();
  }
}

const now = () => new Date().toISOString();
const NODE_TOKENS_KEPT = 5;

function toAgent(row: Record<string, unknown>): Agent {
  return {
    id: String(row.id),
    name: String(row.name),
    gid: Number(row.gid),
    keyId: String(row.key_id),
    recoveryHash: row.recovery_hash === null ? null : String(row.recovery_hash),
    guest: Number(row.guest) === 1,
    groups: row.groups === null || row.groups === undefined ? null : (JSON.parse(String(row.groups)) as number[]),
  };
}
