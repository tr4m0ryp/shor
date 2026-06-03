/**
 * Aegis dashboard HTTP server entry (mirrors storron's framework-less Node
 * `http` server, `apps/web/src/index.ts`).
 *
 * Parses each request into `(method, url, body, cookieHeader)`, delegates to the
 * pure `apiRouter`, and writes the `{ status, body, setCookie? }` envelope. The
 * router authenticates + tenant-scopes via the `auth` middleware (ADR-044).
 */

import { existsSync, readFileSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isGateExempt, isUnlocked } from '../auth/gate.js';
import { getConfig } from '../config.js';
import { apiRouter } from './router.js';

const PORT = Number.parseInt(process.env.WEB_PORT ?? '3457', 10);

/** Static asset root: `dist/public` next to this compiled module. */
const PUBLIC_DIR = join(fileURLToPath(import.meta.url), '..', '..', 'public');

const MIME_TYPES: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

/**
 * Resolve a static asset for a GET path, or `null` to fall through to the API
 * router. Serves `index.html` for `/` and asset requests (anything with a known
 * extension); leaves extension-less paths (`/projects`, `/auth/me`) for the API.
 * Paths are normalized and confined to `PUBLIC_DIR` (no `..` traversal).
 */
function serveStatic(pathname: string): { body: Buffer; mime: string } | null {
  const isRoot = pathname === '/' || pathname === '';
  const ext = extname(pathname);
  if (!isRoot && !ext) return null; // an API path, not an asset

  const rel = isRoot ? 'index.html' : pathname.replace(/^\/+/, '');
  const filePath = normalize(join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR) || !existsSync(filePath)) return null;

  const mime = MIME_TYPES[extname(filePath)] ?? 'application/octet-stream';
  return { body: readFileSync(filePath), mime };
}

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
      // App-wide passcode gate: when locked, a navigation must NOT receive any
      // static asset (the SPA must not load while locked), so the gate decision
      // runs BEFORE static serving. Exempt paths (`/share/*`, `/gate`, Bearer
      // clients) and the disabled case fall straight through to normal serving.
      // The actual unlock page / 401 is produced by `apiRouter` below so all
      // gate logic stays in one place.
      const pathname = new URL(url, 'http://localhost').pathname;
      const gateParts = pathname.split('/').filter(Boolean);
      // Mirror the router's `/api`-prefix strip so the exempt check matches.
      const gateSegments = gateParts[0] === 'api' ? gateParts.slice(1) : gateParts;
      const gateLocked = !isGateExempt(gateSegments, req.headers.authorization) && !isUnlocked(req.headers.cookie);

      // Static assets (the ported dashboard UI) for GET requests to `/` or an
      // asset path; extension-less GETs fall through to the API router. Skipped
      // when the gate is locked so the unlock page is served instead.
      if (method === 'GET' && !gateLocked) {
        const file = serveStatic(pathname);
        if (file) {
          const headers: Record<string, string> = { 'Content-Type': file.mime };
          // No HTML caching so a rebuilt dashboard bundle never sticks.
          if (file.mime.startsWith('text/html')) headers['Cache-Control'] = 'no-store, must-revalidate';
          res.writeHead(200, headers);
          res.end(file.body);
          return;
        }
      }

      const body = method === 'POST' || method === 'PUT' ? await parseBody(req) : {};
      const result = await apiRouter(
        method,
        url,
        body,
        req.headers.cookie,
        req.headers.authorization,
        req.headers.accept,
      );
      // Browser-redirect responses (GitHub OAuth + gate unlock): emit a 302 to
      // `Location` instead of the JSON body, carrying any `Set-Cookie` along.
      if (result.redirect) {
        res.writeHead(302, {
          Location: result.redirect,
          ...(result.setCookie ? { 'Set-Cookie': result.setCookie } : {}),
        });
        res.end();
        return;
      }
      // Inline HTML responses (the passcode gate's unlock page) — served as
      // `text/html`, never cached so a stale lock screen cannot stick.
      if (result.html !== undefined) {
        res.writeHead(result.status, {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store, must-revalidate',
          ...(result.setCookie ? { 'Set-Cookie': result.setCookie } : {}),
        });
        res.end(result.html);
        return;
      }
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
