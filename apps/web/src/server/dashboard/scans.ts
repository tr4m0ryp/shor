/**
 * Dashboard scan-detail API (LAUNCH-SPEC §5/§6, ADR-015).
 *
 * Per-scan reads behind the run-detail view: the scan's findings (§6.1 records)
 * and its attack-surface document (kill chains + scenarios with the remediation
 * "fix" prompt, ADR-010). All authenticated + tenant-scoped via `gate()`.
 */

import { getConfig } from '../../config.js';
import { attackSurfaceRepo, findingRepo, scanRepo } from '../../db/repositories/index.js';
import type { ScanId } from '../../domain/types.js';
import type { ApiResponse } from '../router.js';
import { gate, notFound, ok, serverError } from './auth-util.js';

/**
 * `GET /scans/:id/report` — the Sinas-finalized executive report for the scan.
 * The finalizer (apps/worker .../sinas-finalization.ts) writes the structured
 * report to the `<ns>/reports` Sinas store keyed by scanId; this proxies that
 * server-side (the browser never holds the Sinas key). Tenant-scoped: the scan
 * row is checked first, so a caller only reads reports for their own scans.
 * Returns `{ report: null }` (not 404) when Sinas is unconfigured or no report
 * has been finalized yet.
 */
/**
 * Fetch the Sinas-finalized report for `scanId` from the `<ns>/reports` store,
 * or `null` when Sinas is unconfigured / no report exists. Server-side only (the
 * browser never holds the Sinas key). Shared by the authed and the share routes;
 * the CALLER is responsible for the scan-ownership/tenant check.
 */
export async function fetchSinasReport(scanId: string): Promise<unknown | null> {
  const { sinasUrl, sinasApiKey, sinasNamespace } = getConfig().sinas;
  if (!sinasUrl || !sinasApiKey) return null;
  const base = sinasUrl.replace(/\/+$/, '');
  const ns = sinasNamespace || 'pentest';
  const res = await fetch(`${base}/stores/${ns}/reports/states/${encodeURIComponent(scanId)}`, {
    headers: { 'X-API-Key': sinasApiKey },
  });
  if (!res.ok) return null;
  const body = (await res.json().catch(() => null)) as { value?: unknown } | null;
  return body && typeof body === 'object' ? (body.value ?? body) : null;
}

export async function getScanReport(scanId: ScanId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const scan = await scanRepo.findById(g.tenantId, scanId);
    if (!scan) return notFound('scan not found');
    return ok({ report: await fetchSinasReport(scanId) });
  } catch (err) {
    return serverError(err);
  }
}

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

