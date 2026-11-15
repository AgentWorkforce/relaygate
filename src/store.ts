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
}

export class Store {
  private db: DatabaseSync;

  /** `readOnly` opens an existing database without creating or migrating anything (for the explain CLI). */
  constructor(path: string, opts: { readOnly?: boolean } = {}) {
    this.db = new DatabaseSync(path, { readOnly: opts.readOnly ?? false });
    if (opts.readOnly) return;
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
  }

  private addColumn(table: string, column: string, decl: string): void {
    const cols = this.db.prepare(`PRAGMA table_info(${table})`).all().map((c) => String(c.name));
    if (!cols.includes(column)) this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  }

  ping(): boolean {
    return this.db.prepare("SELECT 1 AS ok").get()?.ok === 1;
  }

  agentByName(name: string): Agent | undefined {
    const row = this.db.prepare("SELECT id, name, gid, key_id, recovery_hash, guest FROM agents WHERE name = ?").get(name);
    return row ? toAgent(row) : undefined;
  }

  createAgent(name: string, gid: number, keyId: string, recovery: string | undefined, guest = false): Agent {
    const agent: Agent = {
      id: `ag_${randomUUID()}`,
      name,
      gid,
      keyId,
      recoveryHash: recovery ? sha256(recovery) : null,
      guest,
    };
    this.db
      .prepare("INSERT INTO agents (id, name, gid, key_id, recovery_hash, guest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(agent.id, agent.name, agent.gid, agent.keyId, agent.recoveryHash, agent.guest ? 1 : 0, now());
    return agent;
  }

  /** Revokes every token the agent holds and returns the hashes that were revoked. */
  revokeTokens(agentId: string): string[] {
    const rows = this.db.prepare("SELECT hash FROM tokens WHERE agent_id = ? AND revoked = 0").all(agentId);
    this.db.prepare("UPDATE tokens SET revoked = 1 WHERE agent_id = ?").run(agentId);
    return rows.map((r) => String(r.hash));
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

  issueToken(agentId: string): string {
    const token = `rg_${randomBytes(32).toString("base64url")}`;
    this.db.prepare("INSERT INTO tokens (hash, agent_id, created_at) VALUES (?, ?, ?)").run(sha256(token), agentId, now());
    return token;
  }

  agentForToken(token: string): Agent | undefined {
    return this.agentForTokenHash(sha256(token));
  }

  agentForTokenHash(hash: string): Agent | undefined {
    const row = this.db
      .prepare(
        "SELECT a.id, a.name, a.gid, a.key_id, a.recovery_hash, a.guest FROM tokens t JOIN agents a ON a.id = t.agent_id WHERE t.hash = ? AND t.revoked = 0",
      )
      .get(hash);
    return row ? toAgent(row) : undefined;
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

  audit(e: AuditEntry): void {
    this.db
      .prepare(
        "INSERT INTO audit (at, agent_id, action, op, resource_kind, resource_id, decision, stage, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(now(), e.agentId, e.action, e.op, e.resourceKind, e.resourceId, e.decision, e.stage, e.reason);
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
  };
}
