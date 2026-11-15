import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { AclEntry } from "./mode.js";

export const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

export function sameHash(a: string, b: string): boolean {
  const x = Buffer.from(a, "hex");
  const y = Buffer.from(b, "hex");
  return x.length === y.length && timingSafeEqual(x, y);
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
    const row = this.db
      .prepare(
        "SELECT a.id, a.name, a.gid, a.key_id, a.recovery_hash, a.guest FROM tokens t JOIN agents a ON a.id = t.agent_id WHERE t.hash = ? AND t.revoked = 0",
      )
      .get(sha256(token));
    return row ? toAgent(row) : undefined;
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
