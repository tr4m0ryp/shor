/**
 * Public read-only share routes (guest links) — NO authentication.
 *
 * A dashboard owner mints an opaque `share_slug` on a project (`POST
 * /projects/:id/share`). Anyone holding `/<...>?share=<slug>` may READ that ONE
 * project plus its scans / findings / attack-surface / progress with no
 * session cookie and no ability to mutate anything. Mirrors the authed dashboard
 * read handlers (`server/dashboard/projects.ts`, `scans.ts`, `scan-progress`)
 * but resolves a slug instead of a session.
 *
 * SECURITY INVARIANTS (load-bearing):
 *   - The slug is the sole access key; `findByShareSlug` is NOT tenant-scoped.
 *   - Internally every per-scan read still passes the resolved project's
 *     `tenantId` to the repositories, so no cross-tenant row is ever reachable.
 *   - CRITICAL: every per-scan route re-verifies `scan.projectId === project.id`
 *     so a slug for project A can never read project B's scans, even within the
 *     same tenant.
 *   - All routes are GET-only; any other method → 405. There is no write path.
 */

import { attackSurfaceRepo, findingRepo, projectRepo, scanRepo } from '../db/repositories/index.js';
import { deriveProgressView } from '../scan-progress/index.js';
import { fetchSinasReport } from './dashboard/scans.js';
import type { ApiResponse } from './router.js';

const methodNotAllowed: ApiResponse = { status: 405, body: { error: 'Method not allowed' } };
const notFound: ApiResponse = { status: 404, body: { error: 'not found' } };
const ok = (body: Record<string, unknown>): ApiResponse => ({ status: 200, body });

function serverError(err: unknown): ApiResponse {
  const msg = err instanceof Error ? err.message : String(err);
  return { status: 500, body: { error: msg } };
}

/**
 * Resolve a share route, or `null` when `segments[0] !== 'share'` (so the parent
 * router falls through). `segments` is the path split with any `/api` prefix
 * already stripped, i.e. `['share', slug, ...rest]`.
 *
 * Shapes (all GET):
 *   /share/:slug/project
 *   /share/:slug/scans
 *   /share/:slug/scans/:scanId
 *   /share/:slug/scans/:scanId/findings
 *   /share/:slug/scans/:scanId/attack-surface
 *   /share/:slug/scans/:scanId/progress
 */
export async function routeShare(method: string, segments: readonly string[]): Promise<ApiResponse | null> {
  if (segments[0] !== 'share') return null;
  if (method !== 'GET') return methodNotAllowed;

  const slug = segments[1];
  const resource = segments[2];
  if (!slug || !resource) return notFound;

  try {
    const project = await projectRepo.findByShareSlug(slug);
    if (!project) return notFound;

    // /share/:slug/project — the full project doc (safe to expose).
    if (resource === 'project' && segments.length === 3) {
      return ok({ project });
    }

    if (resource === 'scans') {
      const scanId = segments[3];
      // /share/:slug/scans — all scans for the shared project.
      if (!scanId) {
        const scans = await scanRepo.listByProject(project.tenantId, project.id);
        return ok({ scans });
      }
      return routeShareScan(project.tenantId, project.id, scanId, segments[4]);
    }

    return notFound;
  } catch (err) {
    return serverError(err);
  }
}

/**
 * Per-scan share routes. Resolves the scan ONCE and verifies it belongs to the
 * shared project before dispatching, so a slug can never read another project's
 * scan (the cross-tenant + cross-project guard).
 */
async function routeShareScan(
  tenantId: string,
  projectId: string,
  scanId: string,
  sub: string | undefined,
): Promise<ApiResponse> {
  const scan = await scanRepo.findById(tenantId, scanId);
  // CRITICAL ownership check: the scan must belong to THIS shared project.
  if (!scan || scan.projectId !== projectId) return notFound;

  // /share/:slug/scans/:scanId — scan header + finding count.
  if (!sub) {
    const findings = await findingRepo.listByScan(tenantId, scanId);
    return ok({ scan, findingCount: findings.length });
  }

  if (sub === 'findings') {
    const findings = await findingRepo.listByScan(tenantId, scanId);
    return ok({ findings });
  }

  if (sub === 'attack-surface') {
    const surface = await attackSurfaceRepo.findByScan(tenantId, scanId);
    return ok({ attackSurface: surface ? surface.data : { scenarios: [] } });
  }

  if (sub === 'diff') {
    return ok({ diff: await computeShareDiff(tenantId, projectId, scanId) });
  }

  if (sub === 'progress') {
    return ok({ progress: deriveProgressView(scan) });
  }

  if (sub === 'report') {
    return ok({ report: await fetchSinasReport(scanId) });
  }

  return notFound;
}

/**
 * Read-only scan-to-scan diff for a public share. Mirrors the authed
 * `getScanDiff` (new/open/fixed/regressed counts) but uses the PURE
 * `diffFingerprints` set-difference so it performs NO writes — the authed path's
 * `computeStatusTransitions` persists finding statuses, which a guest link must
 * never do. `regressed` is not derivable without mutating the prior row's status
 * read, so it stays 0 here (matches `diffFingerprints`' documented semantics).
 */
async function computeShareDiff(tenantId: string, projectId: string, scanId: string): Promise<DiffResult> {
  const projectScans = await scanRepo.listByProject(tenantId, projectId);
  const index = projectScans.findIndex((s) => s.id === scanId);
  // listByProject is ordered started_at DESC NULLS LAST → prior scan is the next one.
  const priorScanId = index >= 0 && index + 1 < projectScans.length ? (projectScans[index + 1]?.id ?? null) : null;

  const currentFps = await findingRepo.fingerprintsForScan(tenantId, scanId);
  const priorFps = priorScanId ? await findingRepo.fingerprintsForScan(tenantId, priorScanId) : [];
  const sets = diffFingerprints(currentFps, priorFps);

  const currentById = new Map<string, string>();
  for (const f of await findingRepo.listByScan(tenantId, scanId)) currentById.set(f.fingerprint, f.id);

  const transitions = [
    ...sets.new.map((fp) => ({ fingerprint: fp, findingId: currentById.get(fp) ?? null, from: null, to: 'new' as const })),
    ...sets.open.map((fp) => ({
      fingerprint: fp,
      findingId: currentById.get(fp) ?? null,
      from: 'open' as const,
      to: 'open' as const,
    })),
    ...sets.fixed.map((fp) => ({ fingerprint: fp, findingId: null, from: 'open' as const, to: 'fixed' as const })),
  ];

  return {
    scanId,
    priorScanId,
    transitions,
    counts: { new: sets.new.length, open: sets.open.length, fixed: sets.fixed.length, regressed: 0 },
  };
}
