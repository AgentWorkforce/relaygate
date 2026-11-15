import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

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
}

export interface StreamRow {
  id: string;
  owner: string;
  gid: number;
  mode: string;
  classify: boolean;
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

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        gid INTEGER NOT NULL,
        key_id TEXT NOT NULL,
        recovery_hash TEXT,
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
  }

  ping(): boolean {
    return this.db.prepare("SELECT 1 AS ok").get()?.ok === 1;
  }

  agentByName(name: string): Agent | undefined {
    const row = this.db.prepare("SELECT id, name, gid, key_id, recovery_hash FROM agents WHERE name = ?").get(name);
    return row ? toAgent(row) : undefined;
  }

  createAgent(name: string, gid: number, keyId: string, recovery: string | undefined): Agent {
    const agent: Agent = {
      id: `ag_${randomUUID()}`,
      name,
      gid,
      keyId,
      recoveryHash: recovery ? sha256(recovery) : null,
    };
    this.db
      .prepare("INSERT INTO agents (id, name, gid, key_id, recovery_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(agent.id, agent.name, agent.gid, agent.keyId, agent.recoveryHash, now());
    return agent;
  }

  /** Revokes every token the agent holds and returns the hashes that were revoked. */
  revokeTokens(agentId: string): string[] {
    const rows = this.db.prepare("SELECT hash FROM tokens WHERE agent_id = ? AND revoked = 0").all(agentId);
    this.db.prepare("UPDATE tokens SET revoked = 1 WHERE agent_id = ?").run(agentId);
    return rows.map((r) => String(r.hash));
  }

  issueToken(agentId: string): string {
    const token = `rg_${randomBytes(32).toString("base64url")}`;
    this.db.prepare("INSERT INTO tokens (hash, agent_id, created_at) VALUES (?, ?, ?)").run(sha256(token), agentId, now());
    return token;
  }

  agentForToken(token: string): Agent | undefined {
    const row = this.db
      .prepare(
        "SELECT a.id, a.name, a.gid, a.key_id, a.recovery_hash FROM tokens t JOIN agents a ON a.id = t.agent_id WHERE t.hash = ? AND t.revoked = 0",
      )
      .get(sha256(token));
    return row ? toAgent(row) : undefined;
  }

  stream(id: string): StreamRow | undefined {
    const row = this.db.prepare("SELECT id, owner, gid, mode, classify FROM streams WHERE id = ?").get(id);
    if (!row) return undefined;
    return {
      id: String(row.id),
      owner: String(row.owner),
      gid: Number(row.gid),
      mode: String(row.mode),
      classify: Number(row.classify) === 1,
    };
  }

  putStream(s: StreamRow): void {
    this.db
      .prepare(
        `INSERT INTO streams (id, owner, gid, mode, classify, updated_at) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET gid = excluded.gid, mode = excluded.mode, classify = excluded.classify, updated_at = excluded.updated_at`,
      )
      .run(s.id, s.owner, s.gid, s.mode, s.classify ? 1 : 0, now());
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
  };
}
