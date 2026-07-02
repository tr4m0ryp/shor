// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `GET /export/sarif?scan=<scanId>` — SARIF 2.1.0 export endpoint (ADR-033).
 *
 * Authenticates + tenant-scopes via the session cookie, loads the scan's
 * findings, and returns a SARIF log for GitHub code-scanning / CI ingestion.
 * Kept separate from `sarif.ts` so the export logic stays transport-agnostic.
 */

import { authenticate } from '../auth/middleware.js';
import { scopedTenantId } from '../auth/tenant-scope.js';
import { findingRepo, scanRepo } from '../db/repositories/index.js';
import type { ScanId } from '../domain/types.js';
import { type SarifLog, toSarif } from './sarif.js';

/** SARIF export response — body is the SARIF log (or an error envelope). */
export interface SarifExportResponse {
  readonly status: number;
  readonly body: SarifLog | Record<string, unknown>;
}

/**
 * Handle `GET /export/sarif?scan=`. The `scan` query parameter is required;
 * the scan must belong to the caller's tenant (verified via `scanRepo`).
 */
export async function handleSarifExport(
  scanId: string | undefined,
  cookieHeader: string | undefined,
): Promise<SarifExportResponse> {
  const auth = authenticate(cookieHeader);
  if (!auth.ok) {
    return { status: auth.status, body: { error: auth.error } };
  }
  const tenantId = scopedTenantId(auth.principal);

  if (!scanId) {
    return { status: 400, body: { error: 'query parameter "scan" is required' } };
  }

  const scan = await scanRepo.findById(tenantId, scanId as ScanId);
  if (!scan) {
    return { status: 404, body: { error: `scan not found: ${scanId}` } };
  }

  const findings = await findingRepo.listByScan(tenantId, scanId as ScanId);
  return { status: 200, body: toSarif(findings) };
}
