import { createHmac, timingSafeEqual } from "node:crypto";
import { statSync } from "node:fs";
import { labelPolicyVersion, loadPolicyFile, parsePolicy, policyVersion, type Policy } from "./policy.js";
import type { Store } from "./store.js";

/** No policy has been applied yet (pulling from relay-control, nothing cached): relaygate refuses everything. */
export class PolicyUnavailable extends Error {}

export interface PolicyStatus {
  source: "file" | "control";
  /** relay-control's version number (control source only). */
  version?: number;
  /** policyVersion of the policy in force, as audit rows record it. */
  hash?: string;
  appliedAt?: string;
  lastFetchAt?: string;
  lastError?: string;
  lastRejected?: { version?: number; reason: string; at: string };
}

export interface PolicySource {
  /** The policy in force. Throws PolicyUnavailable when there is none. */
  current(): Policy;
  /** Checks for a new policy; never throws, never replaces a good policy with a bad one. Resolves true on a change. */
  refresh(): Promise<boolean>;
  status(): PolicyStatus;
}

const iso = (ms: number) => new Date(ms).toISOString();

/** The policy file (RELAYGATE_POLICY): reloaded when its mtime changes, the last good one kept. */
export class FilePolicySource implements PolicySource {
  private policy: Policy;
  private mtime: number;
  private st: PolicyStatus;

  constructor(
    private readonly path: string,
    private readonly now: () => number = Date.now,
  ) {
    this.policy = loadPolicyFile(path);
    this.mtime = statSync(path).mtimeMs;
    this.st = { source: "file", hash: policyVersion(this.policy), appliedAt: iso(now()) };
  }

  current(): Policy {
    return this.policy;
  }

  async refresh(): Promise<boolean> {
    try {
      const m = statSync(this.path).mtimeMs;
      if (m === this.mtime) return false;
      const next = loadPolicyFile(this.path);
      this.policy = next;
      this.mtime = m;
      this.st = { source: "file", hash: policyVersion(next), appliedAt: iso(this.now()) };
      return true;
    } catch (error) {
      this.st = { ...this.st, lastError: (error as Error).message, lastRejected: { reason: (error as Error).message, at: iso(this.now()) } };
      return false;
    }
  }

  status(): PolicyStatus {
    return this.st;
  }
}

export interface ControlPolicyConfig {
  url: string;
  /** Authenticates relaygate to relay-control and keys the answer's signature. */
  secret: string;
  fetch?: typeof fetch;
  now?: () => number;
  timeoutMs?: number;
}

/** The HMAC relay-control puts in X-Relaycontrol-Signature over the raw answer body. */
export function signPolicyBody(secret: string, body: string): string {
  return `v1=${createHmac("sha256", secret).update(body).digest("hex")}`;
}

function signatureOk(secret: string, body: string, header: string | null): boolean {
  if (!header) return false;
  const want = Buffer.from(signPolicyBody(secret, body));
  const got = Buffer.from(header.trim());
  return want.length === got.length && timingSafeEqual(want, got);
}

/**
 * The policy as relay-control serves it (docs/design/control-owned-policy.md). A version is applied only if its
 * signature verifies, it parses, and it is newer than the one in force. Every applied version is cached in the
 * database, so a restart while relay-control is down keeps enforcing it. With nothing applied or cached, current()
 * throws and relaygate refuses everything.
 */
export class ControlPolicySource implements PolicySource {
  private policy: Policy | undefined;
  private version = 0;
  private st: PolicyStatus = { source: "control" };
  private readonly doFetch: typeof fetch;
  private readonly now: () => number;

  constructor(
    private readonly cfg: ControlPolicyConfig,
    private readonly store: Store,
  ) {
    this.doFetch = cfg.fetch ?? fetch;
    this.now = cfg.now ?? Date.now;
    const cached = store.cachedPolicy();
    if (cached) {
      try {
        if (!signatureOk(cfg.secret, cached.body, cached.signature)) throw new Error("cached policy signature does not verify");
        const parsed = this.parseAnswer(cached.body);
        this.apply(parsed.version, parsed.policy, Date.parse(cached.fetchedAt) || this.now());
      } catch (error) {
        this.st.lastError = `cached policy unusable: ${(error as Error).message}`;
      }
    }
  }

  current(): Policy {
    if (!this.policy) throw new PolicyUnavailable("no policy from relay-control yet");
    return this.policy;
  }

  status(): PolicyStatus {
    return this.st;
  }

  async refresh(): Promise<boolean> {
    const at = this.now();
    this.st.lastFetchAt = iso(at);
    let res: Response;
    try {
      res = await this.doFetch(this.cfg.url, {
        headers: { authorization: `Bearer ${this.cfg.secret}`, ...(this.version ? { "if-none-match": `"${this.version}"` } : {}) },
        signal: AbortSignal.timeout(this.cfg.timeoutMs ?? 5000),
      });
    } catch (error) {
      this.st.lastError = `policy fetch failed: ${(error as Error).name}`;
      return false;
    }
    if (res.status === 304) {
      delete this.st.lastError;
      return false;
    }
    if (res.status !== 200) {
      this.st.lastError = `policy fetch answered ${res.status}`;
      return false;
    }
    let body: string;
    try {
      body = await res.text();
    } catch (error) {
      // Headers arrived, then the body didn't (timeout, dropped connection): nothing to apply.
      this.st.lastError = `policy body read failed: ${(error as Error).name}`;
      return false;
    }
    const reject = (reason: string, version?: number) => {
      this.st.lastError = reason;
      this.st.lastRejected = { version, reason, at: iso(at) };
      return false;
    };
    if (!signatureOk(this.cfg.secret, body, res.headers.get("x-relaycontrol-signature"))) return reject("signature does not verify");
    let parsed: { version: number; policy: Policy };
    try {
      parsed = this.parseAnswer(body);
    } catch (error) {
      let version: number | undefined;
      try {
        const v = JSON.parse(body)?.version;
        version = Number.isSafeInteger(v) ? v : undefined;
      } catch {
        /* not JSON */
      }
      return reject(`policy does not parse: ${(error as Error).message}`, version);
    }
    if (parsed.version === this.version) {
      delete this.st.lastError;
      return false;
    }
    if (parsed.version < this.version) return reject(`version ${parsed.version} is older than ${this.version} in force`, parsed.version);
    this.store.cachePolicy({ version: parsed.version, body, signature: res.headers.get("x-relaycontrol-signature")!, fetchedAt: iso(at) });
    this.apply(parsed.version, parsed.policy, at);
    delete this.st.lastError;
    return true;
  }

  private parseAnswer(body: string): { version: number; policy: Policy } {
    const answer = JSON.parse(body) as { version?: unknown; policy?: unknown };
    if (!Number.isSafeInteger(answer?.version) || (answer.version as number) < 1) throw new Error("version must be a positive integer");
    return { version: answer.version as number, policy: parsePolicy(answer.policy) };
  }

  private apply(version: number, policy: Policy, at: number): void {
    const hash = policyVersion(policy);
    labelPolicyVersion(policy, `c${version}-${hash}`);
    this.policy = policy;
    this.version = version;
    this.st = { ...this.st, source: "control", version, hash: `c${version}-${hash}`, appliedAt: iso(at) };
  }
}
