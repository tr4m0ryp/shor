/**
 * Aegis dashboard HTTP server entry (mirrors storron's framework-less Node
 * `http` server, `apps/web/src/index.ts`).
 *
 * Parses each request into `(method, url, body, cookieHeader)`, delegates to the
 * pure `apiRouter`, and writes the `{ status, body, setCookie? }` envelope. The
 * router authenticates + tenant-scopes via the `auth` middleware (ADR-044).
 */

import { createServer, type IncomingMessage } from 'node:http';
import { getConfig } from '../config.js';
import { apiRouter } from './router.js';

const PORT = Number.parseInt(process.env.WEB_PORT ?? '3457', 10);

function parseBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try {
        const parsed: unknown = JSON.parse(raw);
        resolve(typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {});
      } catch {
        resolve({});
      }
    });
    req.on('error', () => resolve({}));
  });
}

/** Construct (but do not listen on) the dashboard HTTP server. */
export function createDashboardServer(): ReturnType<typeof createServer> {
  return createServer(async (req, res) => {
    const url = req.url ?? '/';
    const method = req.method ?? 'GET';

    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      const body = method === 'POST' || method === 'PUT' ? await parseBody(req) : {};
      const result = await apiRouter(method, url, body, req.headers.cookie);
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (result.setCookie) headers['Set-Cookie'] = result.setCookie;
      res.writeHead(result.status, headers);
      res.end(JSON.stringify(result.body));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: msg }));
    }
  });
}

/** Start the dashboard server (idempotent per process). */
export function startDashboard(port = PORT): void {
  // Touch config early so a misconfigured signing secret surfaces at boot.
  getConfig();
  const server = createDashboardServer();
  server.listen(port, () => {
    // eslint-disable-next-line no-console
    console.log(`Aegis dashboard: http://localhost:${port}`);
  });
}
