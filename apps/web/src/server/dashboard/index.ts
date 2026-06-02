/**
 * Dashboard route dispatcher (Phase 5, ADR-010/013).
 *
 * The data plane behind the ported storron UI. A pure function in the same
 * `(method, segments, body, cookieHeader) -> ApiResponse` shape as the parent
 * `apiRouter`, split out so `server/router.ts` stays thin. Every route here is
 * authenticated + tenant-scoped (each handler calls `gate()` first).
 *
 *   GET    /projects                  list projects (Targets)
 *   POST   /projects                  create project
 *   GET    /projects/:id              get project
 *   PUT    /projects/:id              update project
 *   DELETE /projects/:id              delete project
 *   GET    /projects/:id/scans        list a project's scans
 *   POST   /projects/:id/scan         ingest + trigger a scan
 *   GET    /scans/:id                 scan header + finding count
 *   GET    /scans/:id/findings        scan's findings (GET; POST is the sink)
 *   GET    /scans/:id/attack-surface  scan's attack-surface doc (fix prompts)
 *   GET    /scans/:id/diff            scan-to-scan diff (new/open/fixed/regressed)
 *   GET    /users                     tenant users (multi-user view)
 *   GET    /settings/github           GitHub connection status { connected, login? }
 *   POST   /settings/github           connect a PAT { token } → { connected, login }
 *   DELETE /settings/github           disconnect (delete the PAT)
 *   GET    /github/repos              list the caller's selectable repos
 *
 * The GitHub OAuth web-login routes (`GET /settings/github/{config,start,callback}`)
 * need the full URL (querystring + 302 redirect) and are wired in the parent
 * `server/router.ts` rather than here.
 */

import { getScanProgress } from '../../scan-progress/index.js';
import type { ApiResponse } from '../router.js';
import { methodNotAllowed, notFound } from './auth-util.js';
import { createProject, deleteProject, getProject, listProjectScans, listProjects, updateProject } from './projects.js';
import { getScan, getScanAttackSurface, getScanDiff, listScanFindings } from './scans.js';
import { connectGithub, disconnectGithub, getGithubSettings, listGithubRepos } from './settings.js';
import { triggerScan } from './trigger.js';
import { listUsers } from './users.js';

/**
 * Resolve a dashboard route, or `null` when the path is not a dashboard route
 * (so the parent router can fall through to its own resources / 404). `segments`
 * is the path split with the optional `/api` prefix already stripped.
 */
export async function routeDashboard(
  method: string,
  segments: readonly string[],
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse | null> {
  const resource = segments[0];
  const id = segments[1];
  const sub = segments[2];

  if (resource === 'users') {
    if (segments.length === 1) {
      return method === 'GET' ? listUsers(cookieHeader) : methodNotAllowed;
    }
    return null;
  }

  if (resource === 'projects') {
    return routeProjects(method, id, sub, body, cookieHeader);
  }

  if (resource === 'scans' && id) {
    return routeScans(method, id, sub, cookieHeader);
  }

  // GitHub connection settings: /settings/github
  if (resource === 'settings' && id === 'github' && segments.length === 2) {
    if (method === 'GET') return getGithubSettings(cookieHeader);
    if (method === 'POST') return connectGithub(body, cookieHeader);
    if (method === 'DELETE') return disconnectGithub(cookieHeader);
    return methodNotAllowed;
  }

  // Selectable repos for the connected PAT: /github/repos
  if (resource === 'github' && id === 'repos' && segments.length === 2) {
    return method === 'GET' ? listGithubRepos(cookieHeader) : methodNotAllowed;
  }

  return null;
}

async function routeProjects(
  method: string,
  id: string | undefined,
  sub: string | undefined,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse | null> {
  // Collection: /projects
  if (!id) {
    if (method === 'GET') return listProjects(cookieHeader);
    if (method === 'POST') return createProject(body, cookieHeader);
    return methodNotAllowed;
  }

  // Sub-resources: /projects/:id/scans, /projects/:id/scan
  if (sub === 'scans') {
    return method === 'GET' ? listProjectScans(id, cookieHeader) : methodNotAllowed;
  }
  if (sub === 'scan') {
    return method === 'POST' ? triggerScan(id, body, cookieHeader) : methodNotAllowed;
  }
  if (sub) return notFound('unknown project sub-resource');

  // Item: /projects/:id
  if (method === 'GET') return getProject(id, cookieHeader);
  if (method === 'PUT') return updateProject(id, body, cookieHeader);
  if (method === 'DELETE') return deleteProject(id, cookieHeader);
  return methodNotAllowed;
}

async function routeScans(
  method: string,
  id: string,
  sub: string | undefined,
  cookieHeader: string | undefined,
): Promise<ApiResponse | null> {
  // /scans/:id/findings POST is the connectivity sink (handled by the parent
  // router); only GET is a dashboard read here.
  if (sub === 'findings') {
    return method === 'GET' ? listScanFindings(id, cookieHeader) : null;
  }
  if (sub === 'progress') {
    // POST is the worker sink (handled by the parent router); GET is the feed.
    return method === 'GET' ? getScanProgress(id, cookieHeader) : null;
  }
  if (sub === 'attack-surface') {
    return method === 'GET' ? getScanAttackSurface(id, cookieHeader) : methodNotAllowed;
  }
  if (sub === 'diff') {
    return method === 'GET' ? getScanDiff(id, cookieHeader) : methodNotAllowed;
  }
  if (sub) return null;

  return method === 'GET' ? getScan(id, cookieHeader) : methodNotAllowed;
}
