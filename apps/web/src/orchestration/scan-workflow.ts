// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scan workflow (ADR-019 / ADR-051) — one workflow per scan; cancel = kill.
 *
 * The dashboard mints a scan and starts this workflow on Temporal Cloud. Its
 * single activity launches the per-scan Cloud Run Job and waits for completion.
 * Cancelling the workflow cancels the activity, whose cancellation handler
 * deletes the Job execution (the kill switch).
 *
 * Import-safe: only `@temporalio/workflow` + a type-only import. Activities are
 * referenced through `proxyActivities`, never imported directly, so this module
 * loads cleanly in the Temporal workflow sandbox.
 */

import { CancellationScope, isCancellation, proxyActivities } from '@temporalio/workflow';
import type * as activities from './scan-activities.js';
import type { ScanWorkflowInput } from './scan-types.js';

/** Terminal outcome the workflow returns to callers. */
export type ScanWorkflowResult = {
  readonly scanId: string;
  readonly status: 'completed' | 'cancelled' | 'failed';
  readonly error?: string;
};

const { runScanJobActivity } = proxyActivities<typeof activities>({
  // The scan can run for a long time; rely on heartbeat liveness, and propagate
  // cancellation to the activity so it can delete the Job execution (kill).
  startToCloseTimeout: '24 hours',
  heartbeatTimeout: '2 minutes',
  cancellationType: 'WAIT_CANCELLATION_COMPLETED',
  retry: { maximumAttempts: 1 },
});

/**
 * Launch the per-scan Cloud Run Job and await completion. A workflow
 * cancellation flows into the activity, which kills the run; we then return a
 * `cancelled` result instead of throwing.
 */
export async function scanWorkflow(input: ScanWorkflowInput): Promise<ScanWorkflowResult> {
  try {
    await CancellationScope.cancellable(async () => {
      await runScanJobActivity(input);
    });
    return { scanId: input.scanId, status: 'completed' };
  } catch (err) {
    if (isCancellation(err)) {
      return { scanId: input.scanId, status: 'cancelled' };
    }
    return {
      scanId: input.scanId,
      status: 'failed',
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
