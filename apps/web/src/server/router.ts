/**
 * HTTP API router (mirrors storron's `apps/web/src/api/router.ts` shape).
 *
 * A pure function: `(method, url, body, cookieHeader) -> ApiResponse`. The
 * server entry parses the request, calls this, and writes the result. Phase 3
 * wires the `/auth/*` routes; later phases add their resources to the switch.
 *
 * Every non-auth route is expected to authenticate + tenant-scope via the
 * `auth` middleware before touching a repository (ADR-044).
 */

import { handleLogout, handleMe, handleSessionLogin } from '../auth/routes.js';
import { handleIngestFindings, handleSarifExport } from '../findings/index.js';
import { routeDashboard } from './dashboard/index.js';

/** Standard response envelope: HTTP status, JSON body, optional `Set-Cookie`. */
export interface ApiResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly setCookie?: string;
}

const METHOD_NOT_ALLOWED: ApiResponse = { status: 405, body: { error: 'Method not allowed' } };
const NOT_FOUND: ApiResponse = { status: 404, body: { error: 'Not found' } };

export async function apiRouter(
  method: string,
  url: string,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
  authHeader?: string | undefined,
): Promise<ApiResponse> {
  const parsed = new URL(url, 'http://localhost');
  const parts = parsed.pathname.split('/').filter(Boolean);
  // Accept both the spec paths (`/auth/*`) and an `/api`-prefixed form.
  const segments = parts[0] === 'api' ? parts.slice(1) : parts;

  const resource = segments[0];
  const action = segments[1];

  if (resource === 'auth') {
    return routeAuth(method, action, body, cookieHeader);
  }

  // POST /scans/:id/findings — connectivity-only findings sink (ADR-047).
  // Accepts the worker service token (Authorization: Bearer) or a UI session.
  if (resource === 'scans' && segments[2] === 'findings') {
    if (method !== 'POST') return METHOD_NOT_ALLOWED;
    const scanId = segments[1];
    if (!scanId) return NOT_FOUND;
    return handleIngestFindings(scanId, body, cookieHeader, authHeader);
  }

  // GET /export/sarif?scan=<scanId> — SARIF 2.1.0 export view (ADR-033).
  if (resource === 'export' && action === 'sarif') {
    if (method !== 'GET') return METHOD_NOT_ALLOWED;
    const res = await handleSarifExport(parsed.searchParams.get('scan') ?? undefined, cookieHeader);
    return { status: res.status, body: { ...res.body } };
  }

  // Dashboard data plane (Phase 5): projects, scans, findings/attack-surface,
  // diff, trigger, users. Returns null when the path is not a dashboard route.
  const dashboard = await routeDashboard(method, segments, body, cookieHeader);
  if (dashboard) return dashboard;

  return NOT_FOUND;
}

async function routeAuth(
  method: string,
  action: string | undefined,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse> {
  switch (action) {
    case 'session':
      if (method === 'POST') return handleSessionLogin(body);
      return METHOD_NOT_ALLOWED;
    case 'logout':
      if (method === 'POST') return handleLogout();
      return METHOD_NOT_ALLOWED;
    case 'me':
      if (method === 'GET') return handleMe(cookieHeader);
      return METHOD_NOT_ALLOWED;
    default:
      return NOT_FOUND;
  }
}
