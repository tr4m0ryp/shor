// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `GET /external/scans/:id` — Sinas reads a scan's status.
 *
 * The token-authed counterpart of the dashboard's `GET /scans/:id` read, scoped
 * to the resolved showcase/owner tenant (so it can only ever see that tenant's
 * scans). Returns the scan's live status + progress snapshot plus the finding
 * count, mirroring the dashboard's run-detail header read.
 *
 * Returns `{ scanId, status, progress, findingCount, startedAt, finishedAt }`.
 */

import type { Principal } from '../../auth/index.js';
import { findingRepo, scanRepo } from '../../db/repositories/index.js';
import type { ScanId } from '../../domain/types.js';
import { notFound, ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

export async function getExternalScan(principal: Principal, scanId: ScanId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const scan = await scanRepo.findById(tenantId, scanId);
    if (!scan) return notFound('scan not found');
    const findings = await findingRepo.listByScan(tenantId, scanId);
    return ok({
      scanId: scan.id,
      status: scan.status,
      progress: scan.progress,
      findingCount: findings.length,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
    });
  } catch (err) {
    return serverError(err);
  }
}
