/**
 * HTTP front for the MCP connector — a stateless Streamable-HTTP endpoint at
 * `/mcp`, guarded by the pluggable authenticator, plus an unauthenticated health
 * probe for Cloud Run.
 *
 * Stateless: every POST builds a fresh server + transport (no session store), so
 * the connector scales horizontally behind Cloud Run with no sticky sessions.
 * `GET`/`DELETE /mcp` have no session to stream or terminate here and return 405.
 * The auth check runs BEFORE any MCP handling; a failure returns 401 (carrying a
 * `WWW-Authenticate` when the authenticator supplies one — the OAuth hook).
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { getAuthenticator } from './auth.js';
import { getConfig } from './config.js';
import { buildServer } from './server.js';

const MCP_PATH = '/mcp';

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

function jsonRpcError(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  // JSON-RPC-shaped error so MCP clients surface it cleanly (id null, no request context).
  sendJson(res, status, { jsonrpc: '2.0', error: { code: -32000, message }, id: null }, headers);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return undefined;
  return JSON.parse(raw) as unknown;
}

/** Handle one POST /mcp: authorize, then run it through a fresh stateless transport. */
async function handleMcpPost(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let body: unknown;
  try {
    body = await readBody(req);
  } catch {
    jsonRpcError(res, 400, 'invalid JSON body');
    return;
  }

  // Fresh server + transport per request (stateless mode: no session id generator).
  const server = buildServer();
  // Omitting sessionIdGenerator selects stateless mode; JSON responses (not SSE)
  // keep simple request/response tools robust for both Claude Code and claude.ai.
  const transport = new StreamableHTTPServerTransport({ enableJsonResponse: true });
  res.on('close', () => {
    void transport.close();
    void server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, body);
}

export function createMcpHttpServer(): ReturnType<typeof createServer> {
  return createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const method = req.method ?? 'GET';

      // Unauthenticated health probe (Cloud Run startup/liveness).
      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/healthz')) {
        sendJson(res, 200, { ok: true, service: 'shor-mcp' });
        return;
      }

      if (url.pathname !== MCP_PATH) {
        jsonRpcError(res, 404, 'not found');
        return;
      }

      // Auth gate — runs before any MCP handling.
      const auth = getAuthenticator().authenticate(req.headers.authorization);
      if (!auth.ok) {
        jsonRpcError(res, auth.status ?? 401, auth.message ?? 'unauthorized', auth.wwwAuthenticate ? { 'www-authenticate': auth.wwwAuthenticate } : {});
        return;
      }

      if (method === 'POST') {
        await handleMcpPost(req, res);
        return;
      }
      // Stateless: nothing to stream (GET) or terminate (DELETE).
      jsonRpcError(res, 405, 'method not allowed', { allow: 'POST' });
    })().catch((err: unknown) => {
      if (!res.headersSent) jsonRpcError(res, 500, err instanceof Error ? err.message : String(err));
    });
  });
}

export function startMcpHttpServer(): void {
  const { port } = getConfig();
  createMcpHttpServer().listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`shor-mcp listening on :${port} (POST ${MCP_PATH})`);
  });
}
