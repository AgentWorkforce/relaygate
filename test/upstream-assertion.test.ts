import { describe, expect, it } from "vitest";
import { signUpstreamAssertion, verifyUpstreamAssertion } from "../src/upstream-assertion.js";

const KEY = "assertion-test-key-000000000000000000000000";
const KID = "current-1";
const NOW = 1_800_000_000_000;
const request = {
  method: "GET",
  path: "/v1/events?session=s-1&limit=5",
  credential: "Bearer rth_at_read_test",
  audience: "session-read-api" as const,
  principal: { agentId: "ag_1", gid: 11, groups: [33, 22, 22] },
  access: "read" as const,
  sessionIds: ["s-1", "s-1"],
};

describe("relaygate upstream assertions", () => {
  it("binds a short-lived signed claim to route, credential, principal and session scope", () => {
    const token = signUpstreamAssertion({ key: KEY, kid: KID, ttlSeconds: 30, now: () => NOW }, request);
    const claims = verifyUpstreamAssertion(token, new Map([[KID, KEY]]), request, NOW + 10_000);
    expect(claims).toMatchObject({
      v: 1,
      iss: "relaygate",
      aud: "session-read-api",
      kid: KID,
      iat: NOW / 1000,
      exp: NOW / 1000 + 30,
      method: "GET",
      path: request.path,
      principal: { agent_id: "ag_1", gid: 11, groups: [22, 33] },
      access: "read",
      session_ids: ["s-1"],
    });
  });

  it("rejects tampering, replay on another request or credential, wrong scope, expiry and unknown rotation keys", () => {
    const token = signUpstreamAssertion({ key: KEY, kid: KID, ttlSeconds: 30, now: () => NOW }, request);
    const keys = new Map([[KID, KEY]]);
    const bad = [
      { ...request, method: "POST" },
      { ...request, path: "/v1/events?session=s-2&limit=5" },
      { ...request, credential: "Bearer another" },
      { ...request, audience: "ingest-edge" as const },
      { ...request, access: "filter" as const },
      { ...request, sessionIds: ["s-2"] },
    ];
    for (const changed of bad) expect(() => verifyUpstreamAssertion(token, keys, changed, NOW)).toThrow("invalid upstream assertion");
    expect(() => verifyUpstreamAssertion(token, keys, request, NOW + 31_000)).toThrow("invalid upstream assertion");
    expect(() => verifyUpstreamAssertion(token, new Map([["previous", KEY]]), request, NOW)).toThrow("invalid upstream assertion");
    expect(() => verifyUpstreamAssertion(token.slice(0, -1) + (token.endsWith("a") ? "b" : "a"), keys, request, NOW)).toThrow("invalid upstream assertion");
  });

  it("binds write assertions to the exact bytes", () => {
    const write = { ...request, method: "POST", path: "/v1/delivery/batches", body: Buffer.from("compressed-bytes"), audience: "ingest-edge" as const, access: "write" as const };
    const token = signUpstreamAssertion({ key: KEY, kid: KID, now: () => NOW }, write);
    expect(verifyUpstreamAssertion(token, new Map([[KID, KEY]]), write, NOW).body_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(() => verifyUpstreamAssertion(token, new Map([[KID, KEY]]), { ...write, body: Buffer.from("different") }, NOW)).toThrow();
  });
});
