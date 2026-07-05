// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * External Sinas->engine ingress (two-way Sinas integration, design T1/T7/T8/T9).
 *
 * Bearer-authed HTTP surface that lets a Sinas instance drive the engine without
 * a browser session: rerun/start a scan, create a project (black-box or white-box
 * via a connected GitHub repo), read a scan's status/results, list projects and
 * their scan history, cancel a running scan, and list the tenant's connected
 * repos. The engine stays the single source of truth — it MINTS every id
 * (scanId/projectId) and never accepts a client-supplied one.
 *
 *   POST /external/scans                    { projectId, ref?, provider? } -> { scanId, status }
 *   POST /external/scans/:id/cancel         -> { scanId, status }  (operator kill switch)
 *   POST /external/projects                 { name, targetUrl, mode, repoRef? } -> { projectId }
 *   GET  /external/scans                    -> { runs: [...] }  (active runs)
 *   GET  /external/scans/:id                -> { status, progress, ... }
 *   GET  /external/scans/:id/findings       -> { findings: [...] }
 *   GET  /external/scans/:id/report         -> { report: <obj>|null }
 *   GET  /external/scans/:id/attack-surface -> { attackSurface: {...} }
 *   GET  /external/projects                 -> { projects: [...] }
 *   GET  /external/projects/:id/scans       -> { scans: [...] }
 *   GET  /external/github/repos             -> { repos: [...] }
 *
 * The read + cancel routes are the token-authed counterparts of the dashboard
 * run-detail / Targets reads. Cancel only REDUCES activity, so — like the reads —
 * the engine bearer alone authorizes it; only the START path additionally demands
 * the single-use human launch token.
 *
 * Auth: a single `Authorization: Bearer <SHOR_ENGINE_TRIGGER_TOKEN>` guards the
 * whole `/external/*` plane, validated EXACTLY like the findings/progress sink
 * validates `SHOR_SINK_TOKEN` (constant-time compare, 401 on missing/mismatch,
 * the token is never logged). The token is scoped to start + create + read only;
 * nothing here deletes or mutates existing data.
 *
 * Tenant: there is no session under token auth. Every `/external/*` call resolves
 * the single configured showcase/owner tenant the SAME way the codebase already
 * gets the owner principal (`ensureDevSession` — idempotent find-or-create of the
 * owner tenant + user), reusing its `tenantId` for scoping and its `uid` as the
 * GitHub-token owner for white-box ingest (mirrors how the dashboard's trigger
 * passes `principal.uid` to `ingestForScan`).
 */

import type { Principal } from '../../auth/index.js';
import { ensureDevSession } from '../../auth/index.js';
import { getConfig } from '../../config.js';
import type { ApiResponse } from '../router.js';
import { cancelExternalScan } from './cancel-scan.js';
import { createExternalProject } from './create-project.js';
import { getExternalScan } from './get-scan.js';
import { launchExternalScan } from './launch.js';
import { listActiveExternalScans } from './list-active-scans.js';
import { listExternalRepos } from './list-repos.js';
import { listExternalProjects, listExternalProjectScans } from './projects-read.js';
import {
  getExternalScanAttackSurface,
  getExternalScanFindings,
  getExternalScanReport,
} from './scan-results.js';
import { shareExternalProject } from './share.js';
import { startExternalScan } from './start-scan.js';

const UNAUTHORIZED: ApiResponse = { status: 401, body: { error: 'unauthorized' } };
const NOT_FOUND: ApiResponse = { status: 404, body: { error: 'Not found' } };
const METHOD_NOT_ALLOWED: ApiResponse = { status: 405, body: { error: 'Method not allowed' } };

/** Parse a `Bearer <token>` Authorization header; returns the token or undefined. */
function bearerToken(authHeader: string | undefined): string | undefined {
  if (!authHeader) return undefined;
  const m = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  return m ? m[1] : undefined;
}

/**
 * Length-independent, timing-safe-ish string equality. Never short-circuits on
 * the first differing byte and never logs either operand — identical to the
 * sink's `safeEqual`, used to compare the presented trigger token against the
 * configured `engineTriggerToken`.
 */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Authorize an `/external/*` request against `SHOR_ENGINE_TRIGGER_TOKEN`. An
 * empty configured token disables the whole ingress (every request 401s) so a
 * misconfigured deployment can never be driven anonymously — exactly the sink's
 * `sinkToken !== ''` guard.
 */
export function authorizeExternal(authHeader: string | undefined): boolean {
  const { engineTriggerToken } = getConfig().sinas;
  if (engineTriggerToken === '') return false;
  const presented = bearerToken(authHeader);
  return presented !== undefined && safeEqual(presented, engineTriggerToken);
}

/**
 * Resolve the principal for token-authed external calls: the single configured
 * showcase/owner tenant + user. Reuses `ensureDevSession` (idempotent) so the
 * ingress and the dashboard agree on the same tenant/user ids.
 */
async function resolveExternalPrincipal(): Promise<Principal> {
  return ensureDevSession();
}

/**
 * Dispatch an `/external/*` route, or `null` when the path is not an external
 * route (so the parent router falls through). The bearer guard runs FIRST: a
 * missing/wrong token 401s before any handler or tenant resolution.
 *
 * `segments` is the path split with the optional `/api` prefix already stripped
 * (so `segments[0] === 'external'`).
 */
export async function routeExternal(
  method: string,
  segments: readonly string[],
  body: Record<string, unknown>,
  authHeader: string | undefined,
): Promise<ApiResponse | null> {
  if (segments[0] !== 'external') return null;

  if (!authorizeExternal(authHeader)) return UNAUTHORIZED;

  const principal = await resolveExternalPrincipal();
  const resource = segments[1];
  const id = segments[2];
  const sub = segments[3];

  // POST /external/launch — the token-GATED black-box launch (MCP connector).
  // Requires a valid single-use launch token in the body ON TOP of the bearer;
  // this is the only start path that enforces human approval.
  if (resource === 'launch' && !id) {
    return method === 'POST' ? launchExternalScan(principal, body) : METHOD_NOT_ALLOWED;
  }

  // POST /external/projects/:id/share — mint/read the read-only guest link.
  if (resource === 'projects' && id && sub === 'share') {
    return method === 'POST' ? shareExternalProject(principal, id) : METHOD_NOT_ALLOWED;
  }

  // GET /external/projects/:id/scans — the project's scan history, newest first.
  if (resource === 'projects' && id && sub === 'scans') {
    return method === 'GET' ? listExternalProjectScans(principal, id) : METHOD_NOT_ALLOWED;
  }

  // /external/scans (no id): POST starts a scan; GET lists the tenant's ACTIVE runs.
  if (resource === 'scans' && !id) {
    if (method === 'POST') return startExternalScan(principal, body);
    if (method === 'GET') return listActiveExternalScans(principal);
    return METHOD_NOT_ALLOWED;
  }

  // /external/scans/:id — bare GET is the status snapshot; the sub-routes cancel
  // the run or read its results (findings / report / attack-surface).
  if (resource === 'scans' && id) {
    if (sub === 'cancel') {
      return method === 'POST' ? cancelExternalScan(principal, id) : METHOD_NOT_ALLOWED;
    }
    if (sub === 'findings') {
      return method === 'GET' ? getExternalScanFindings(principal, id) : METHOD_NOT_ALLOWED;
    }
    if (sub === 'report') {
      return method === 'GET' ? getExternalScanReport(principal, id) : METHOD_NOT_ALLOWED;
    }
    if (sub === 'attack-surface') {
      return method === 'GET' ? getExternalScanAttackSurface(principal, id) : METHOD_NOT_ALLOWED;
    }
    if (!sub) {
      return method === 'GET' ? getExternalScan(principal, id) : METHOD_NOT_ALLOWED;
    }
    return NOT_FOUND;
  }

  // /external/projects (no id): POST creates a project; GET lists them.
  if (resource === 'projects' && !id) {
    if (method === 'POST') return createExternalProject(principal, body);
    if (method === 'GET') return listExternalProjects(principal);
    return METHOD_NOT_ALLOWED;
  }

  // GET /external/github/repos — the tenant's connected repos.
  if (resource === 'github' && id === 'repos') {
    return method === 'GET' ? listExternalRepos(principal) : METHOD_NOT_ALLOWED;
  }

  return NOT_FOUND;
}
