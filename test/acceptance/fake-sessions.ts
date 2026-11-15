/**
 * An in-memory stand-in for the Sessions API, for dry-running scripts/acceptance against a local relaygate when no
 * real Sessions deployment is at hand. Only the routes relaygate proxies; no auth beyond requiring a bearer token.
 *
 *   PORT=8790 node test/acceptance/fake-sessions.ts
 */
import { createServer, type Server } from "node:http";

export function fakeSessionsServer(): Server {
  const sessions = new Map<string, Array<Record<string, unknown>>>();
  return createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://sessions");
  const send = (status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  if (!req.headers.authorization?.startsWith("Bearer ")) return send(401, { error: { code: "unauthorized" } });
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;

  const turns = url.pathname.match(/^\/v1\/sessions\/([^/]+)\/turns$/);
  if (req.method === "POST" && turns) {
    const id = decodeURIComponent(turns[1]!);
    sessions.set(id, [...(sessions.get(id) ?? []), ...(body?.turns ?? [])]);
    return send(200, { accepted: body?.turns?.length ?? 0 });
  }
  if (req.method === "POST" && url.pathname === "/v1/ingest") {
    for (const r of body?.records ?? []) sessions.set(r.sessionId, [...(sessions.get(r.sessionId) ?? []), r]);
    return send(200, { batchId: body?.batchId, received: body?.records?.length ?? 0 });
  }
  if (req.method === "GET" && url.pathname === "/v1/sessions") {
    return send(200, { sessions: [...sessions.keys()].map((sessionId) => ({ sessionId })), nextCursor: null });
  }
  const view = url.pathname.match(/^\/v1\/sessions\/([^/]+)\/(events|turns|metadata|thread|catalog|timing|analysis|brief)$/);
  if (req.method === "GET" && view) {
    const id = decodeURIComponent(view[1]!);
    if (!sessions.has(id)) return send(404, { error: { code: "not_found" } });
    return send(200, { sessionId: id, [view[2]!]: sessions.get(id) });
  }
  if (req.method === "GET" && url.pathname === "/v1/events") {
    const id = url.searchParams.get("session") ?? "";
    return send(200, { events: sessions.get(id) ?? [] });
  }
  send(404, { error: { code: "not_found" } });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT ?? 8790);
  fakeSessionsServer().listen(port, () => console.log(`fake sessions on ${port}`));
}
