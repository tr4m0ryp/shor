// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Token-authed read of a scan's RESULTS for Sinas/MCP: the finding records, the
 * finalized executive report, and the attack-surface document. These are the
 * `/external/*` counterparts of the dashboard's run-detail reads (dashboard
 * `scans.ts`), scoped to the resolved showcase/owner tenant so a caller only ever
 * sees its own scans. All read-only — none mutates scanning state.
 *
 *   GET /external/scans/:id/findings        -> { findings: [...] }
 *   GET /external/scans/:id/report          -> { report: <obj>|null }
 *   GET /external/scans/:id/attack-surface  -> { attackSurface: { scenarios, ... } }
 *
 * Report / attack-surface return `null` / an empty document (not 404) when the
 * scan exists but finalization/synthesis has not landed yet — the same "exists
 * but not ready" contract the dashboard uses.
 */

import type { Principal } from '../../auth/index.js';
import { attackSurfaceRepo, findingRepo, scanRepo } from '../../db/repositories/index.js';
import type { ScanId } from '../../domain/types.js';
import { notFound, ok, serverError } from '../dashboard/auth-util.js';
import { fetchSinasReport } from '../dashboard/scans.js';
import type { ApiResponse } from '../router.js';

/** `GET /external/scans/:id/findings` — the scan's finding records. */
export async function getExternalScanFindings(principal: Principal, scanId: ScanId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const scan = await scanRepo.findById(tenantId, scanId);
    if (!scan) return notFound('scan not found');
    const findings = await findingRepo.listByScan(tenantId, scanId);
    return ok({ findings });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /external/scans/:id/report` — the finalized executive report, or null. */
export async function getExternalScanReport(principal: Principal, scanId: ScanId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const scan = await scanRepo.findById(tenantId, scanId);
    if (!scan) return notFound('scan not found');
    // Prefer the DB-persisted report (worker sink posts it); fall back to the
    // legacy Sinas store for any pre-migration scan (decommissioned → null).
    const report = (await scanRepo.getReport(tenantId, scanId)) ?? (await fetchSinasReport(scanId));
    return ok({ report });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /external/scans/:id/attack-surface` — scenarios + kill chains, or empty. */
export async function getExternalScanAttackSurface(principal: Principal, scanId: ScanId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const scan = await scanRepo.findById(tenantId, scanId);
    if (!scan) return notFound('scan not found');
    const surface = await attackSurfaceRepo.findByScan(tenantId, scanId);
    return ok({ attackSurface: surface ? surface.data : { scenarios: [] } });
  } catch (err) {
    return serverError(err);
  }
}
