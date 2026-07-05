// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `POST /external/scans/:id/cancel` — Sinas/MCP stops a running scan (operator
 * kill switch, ADR-019). This is the token-authed counterpart of the dashboard's
 * operator cancel: it cancels the scan's Cloud Run Job execution AND records the
 * terminal `cancelled` status in one call, so the DB reflects the stop even if
 * the dying worker never posts back.
 *
 * Cancelling only ever REDUCES activity — it can never widen scope — so it does
 * not require the single-use launch token the start path enforces; the engine
 * bearer alone authorizes it (the whole `/external/*` plane is already gated).
 *
 * Idempotent: a scan that is already terminal is returned as-is (no re-cancel);
 * a `pending` scan with no execution is marked `cancelled` (the execution cancel
 * is a no-op). Tenant-scoped: only the resolved tenant's scans are reachable.
 *
 * Returns `{ scanId, status }`.
 */

import type { Principal } from '../../auth/index.js';
import { scanRepo } from '../../db/repositories/index.js';
import type { ScanId, ScanStatus } from '../../domain/types.js';
import { killScan } from '../../guardrails/kill-switch.js';
import { notFound, ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

/** A scan in one of these states has already stopped; cancelling is a no-op. */
function isTerminal(status: ScanStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled' || status === 'archived';
}

export async function cancelExternalScan(principal: Principal, scanId: ScanId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const scan = await scanRepo.findById(tenantId, scanId);
    if (!scan) return notFound('scan not found');
    if (isTerminal(scan.status)) return ok({ scanId: scan.id, status: scan.status });

    // Kill switch: cancels the Cloud Run Job execution (no-op if none recorded)
    // and audits `kill_switch.triggered` with the operator actor. Then stamp the
    // terminal status, which `killScan` itself does not write.
    await killScan(scan, { reason: 'operator', tenantId, actor: principal.uid });
    const updated = await scanRepo.setStatus(tenantId, scanId, 'cancelled');
    return ok({ scanId: scan.id, status: updated?.status ?? 'cancelled' });
  } catch (err) {
    return serverError(err);
  }
}
