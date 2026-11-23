import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { Principal } from "./mode.js";

export const UPSTREAM_ASSERTION_HEADER = "x-relaygate-assertion";
export const UPSTREAM_ASSERTION_VERSION = 1 as const;

export type AssertionAccess = "read" | "write" | "filter" | "aggregate" | "passthrough";
export type AssertionAudience = "session-read-api" | "ingest-edge";

export interface UpstreamAssertionConfig {
  /** HMAC-SHA256 key shared only with the Sessions read and ingest services. */
  key: string;
  /** Rotation identifier; verifiers select the current/previous key by this value. */
  kid: string;
  /** Assertion lifetime in seconds. Defaults to 30; accepted range is 5..60. */
  ttlSeconds?: number;
  now?: () => number;
}

export interface UpstreamAssertionClaims {
  v: typeof UPSTREAM_ASSERTION_VERSION;
  iss: "relaygate";
  aud: AssertionAudience;
  kid: string;
  iat: number;
  exp: number;
  jti: string;
  method: string;
  path: string;
  body_sha256: string;
  credential_sha256: string;
  principal: { agent_id: string; gid: number; groups: number[] };
  access: AssertionAccess;
  /** Exact ids for small requests; empty when the bounded digest representation is used. */
  session_ids: string[];
  session_count: number;
  session_ids_sha256: string;
}

export interface AssertionRequest {
  method: string;
  /** Exact upstream pathname plus query, e.g. `/v1/events?q=x`; fragments are forbidden. */
  path: string;
  body?: string | Uint8Array;
  credential: string;
  audience: AssertionAudience;
  principal: Principal;
  access: AssertionAccess;
  sessionIds?: string[];
}

const sha256 = (value: string | Uint8Array): string => createHash("sha256").update(value).digest("hex");
const input = (payload: string): string => `relaygate-upstream-v1\n${payload}`;
const sessionScope = (ids: string[] | undefined) => {
  const sorted = [...new Set(ids ?? [])].sort();
  const canonical = JSON.stringify(sorted);
  return {
    sorted,
    count: sorted.length,
    digest: sha256(canonical),
    inline: sorted.length <= 16 && Buffer.byteLength(canonical) <= 2048 ? sorted : [],
  };
};

export function signUpstreamAssertion(config: UpstreamAssertionConfig, request: AssertionRequest): string {
  if (config.key.length < 32) throw new Error("upstream assertion key must be at least 32 characters");
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(config.kid)) throw new Error("upstream assertion kid is invalid");
  const ttl = config.ttlSeconds ?? 30;
  if (!Number.isInteger(ttl) || ttl < 5 || ttl > 60) throw new Error("upstream assertion ttl must be 5..60 seconds");
  if (!request.path.startsWith("/") || request.path.includes("#")) throw new Error("upstream assertion path is invalid");
  const iat = Math.floor((config.now?.() ?? Date.now()) / 1000);
  const sessions = sessionScope(request.sessionIds);
  const claims: UpstreamAssertionClaims = {
    v: UPSTREAM_ASSERTION_VERSION,
    iss: "relaygate",
    aud: request.audience,
    kid: config.kid,
    iat,
    exp: iat + ttl,
    jti: randomUUID(),
    method: request.method.toUpperCase(),
    path: request.path,
    body_sha256: sha256(request.body ?? ""),
    credential_sha256: sha256(request.credential),
    principal: {
      agent_id: request.principal.agentId,
      gid: request.principal.gid,
      groups: [...new Set(request.principal.groups)].sort((a, b) => a - b),
    },
    access: request.access,
    session_ids: sessions.inline,
    session_count: sessions.count,
    session_ids_sha256: sessions.digest,
  };
  const payload = Buffer.from(JSON.stringify(claims), "utf8").toString("base64url");
  const mac = createHmac("sha256", config.key).update(input(payload)).digest("base64url");
  return `v1.${payload}.${mac}`;
}

/** Test/upstream-contract helper: verify the MAC and return claims. Request binding is checked by the verifier. */
export function verifyUpstreamAssertion(
  token: string,
  keys: ReadonlyMap<string, string>,
  request: Pick<AssertionRequest, "method" | "path" | "body" | "credential" | "audience"> & { access?: AssertionAccess; sessionIds?: string[] },
  now = Date.now(),
): UpstreamAssertionClaims {
  const match = /^v1\.([A-Za-z0-9_-]{1,16384})\.([A-Za-z0-9_-]{43})$/.exec(token);
  if (!match) throw new Error("invalid upstream assertion");
  let claims: UpstreamAssertionClaims;
  try {
    claims = JSON.parse(Buffer.from(match[1]!, "base64url").toString("utf8")) as UpstreamAssertionClaims;
  } catch {
    throw new Error("invalid upstream assertion");
  }
  const key = claims?.v === 1 && typeof claims.kid === "string" ? keys.get(claims.kid) : undefined;
  if (!key) throw new Error("invalid upstream assertion");
  const expected = createHmac("sha256", key).update(input(match[1]!)).digest();
  const given = Buffer.from(match[2]!, "base64url");
  if (given.toString("base64url") !== match[2] || expected.length !== given.length || !timingSafeEqual(expected, given)) {
    throw new Error("invalid upstream assertion");
  }
  const at = Math.floor(now / 1000);
  const validShape =
    claims.iss === "relaygate" &&
    (claims.aud === "session-read-api" || claims.aud === "ingest-edge") &&
    Number.isInteger(claims.iat) &&
    Number.isInteger(claims.exp) &&
    claims.exp - claims.iat >= 5 &&
    claims.exp - claims.iat <= 60 &&
    typeof claims.jti === "string" &&
    /^[A-Z]+$/.test(claims.method) &&
    typeof claims.path === "string" &&
    claims.path.startsWith("/") &&
    /^[0-9a-f]{64}$/.test(claims.body_sha256) &&
    /^[0-9a-f]{64}$/.test(claims.credential_sha256) &&
    typeof claims.principal?.agent_id === "string" &&
    Number.isInteger(claims.principal?.gid) &&
    Array.isArray(claims.principal?.groups) && claims.principal.groups.every((gid) => Number.isInteger(gid) && gid >= 0) &&
    (["read", "write", "filter", "aggregate", "passthrough"] as unknown[]).includes(claims.access) &&
    Array.isArray(claims.session_ids) &&
    claims.session_ids.length <= 16 &&
    Buffer.byteLength(JSON.stringify(claims.session_ids)) <= 2048 &&
    claims.session_ids.every((id) => typeof id === "string") &&
    Number.isInteger(claims.session_count) &&
    claims.session_count >= 0 &&
    /^[0-9a-f]{64}$/.test(claims.session_ids_sha256);
  if (!validShape || claims.iat > at + 5 || claims.exp <= at) throw new Error("invalid upstream assertion");
  const wantedSessions = request.sessionIds ? sessionScope(request.sessionIds) : undefined;
  if (
    claims.method !== request.method.toUpperCase() ||
    claims.path !== request.path ||
    claims.body_sha256 !== sha256(request.body ?? "") ||
    claims.credential_sha256 !== sha256(request.credential) ||
    claims.aud !== request.audience ||
    (request.access !== undefined && claims.access !== request.access) ||
    (wantedSessions !== undefined &&
      (claims.session_count !== wantedSessions.count ||
        claims.session_ids_sha256 !== wantedSessions.digest ||
        (claims.session_ids.length > 0 && JSON.stringify(claims.session_ids) !== JSON.stringify(wantedSessions.sorted)) ||
        (claims.session_ids.length === 0 && wantedSessions.inline.length > 0)))
  ) {
    throw new Error("invalid upstream assertion");
  }
  return claims;
}
