/**
 * Dashboard scan-detail API (LAUNCH-SPEC §5/§6, ADR-015/032).
 *
 * Per-scan reads behind the run-detail view: the scan's findings (§6.1 records),
 * its attack-surface document (kill chains + scenarios with the remediation
 * "fix" prompt, ADR-010), and the scan-to-scan diff (new/open/fixed/regressed,
 * ADR-032). All authenticated + tenant-scoped via `gate()`.
 */

import { attackSurfaceRepo, findingRepo, scanRepo } from '../../db/repositories/index.js';
import type { ScanId } from '../../domain/types.js';
import { computeStatusTransitions } from '../../findings/index.js';
import type { ApiResponse } from '../router.js';
import { gate, notFound, ok, serverError } from './auth-util.js';

/** `GET /scans/:id` — scan row + finding count (run-detail header). */
export async function getScan(scanId: ScanId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const scan = await scanRepo.findById(g.tenantId, scanId);
    if (!scan) return notFound('scan not found');
    const findings = await findingRepo.listByScan(g.tenantId, scanId);
    return ok({ scan, findingCount: findings.length });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /scans/:id/findings` (GET) — the scan's §6.1 finding records. */
export async function listScanFindings(scanId: ScanId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const scan = await scanRepo.findById(g.tenantId, scanId);
    if (!scan) return notFound('scan not found');
    const findings = await findingRepo.listByScan(g.tenantId, scanId);
    return ok({ findings });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `GET /scans/:id/attack-surface` — the scan's attack-surface document
 * (scenarios + kill chains). Each scenario carries `claude_code_prompt`, now the
 * remediation "fix" prompt the dashboard copies (ADR-010). Returns an empty
 * document (not 404) when synthesis has not landed yet.
 */
export async function getScanAttackSurface(scanId: ScanId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const scan = await scanRepo.findById(g.tenantId, scanId);
    if (!scan) return notFound('scan not found');
    const surface = await attackSurfaceRepo.findByScan(g.tenantId, scanId);
    return ok({ attackSurface: surface ? surface.data : { scenarios: [] } });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `GET /scans/:id/diff` — scan-to-scan diff for the run's project.
 *
 * Resolves the immediately-prior scan for the same project (the scan started
 * before this one), then computes new/open/fixed/regressed transitions via
 * `computeStatusTransitions` (ADR-032). When this is the project's first scan
 * the prior is null and every finding is `new`.
 */
export async function getScanDiff(scanId: ScanId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const scan = await scanRepo.findById(g.tenantId, scanId);
    if (!scan) return notFound('scan not found');

    const projectScans = await scanRepo.listByProject(g.tenantId, scan.projectId);
    const priorScanId = resolvePriorScanId(scan.id, projectScans);

    const result = await computeStatusTransitions(g.tenantId, scanId, priorScanId);
    return ok({ diff: result });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * Find the scan immediately before `scanId` for the project. `listByProject`
 * returns scans ordered by `started_at DESC NULLS LAST`, so the prior scan is
 * the one directly after the current scan in that list. Returns null when the
 * current scan is the oldest (or absent from the list).
 */
function resolvePriorScanId(scanId: ScanId, ordered: readonly { id: ScanId }[]): ScanId | null {
  const index = ordered.findIndex((s) => s.id === scanId);
  if (index < 0 || index + 1 >= ordered.length) return null;
  return ordered[index + 1]?.id ?? null;
}
