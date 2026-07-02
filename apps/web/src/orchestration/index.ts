// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scan orchestration (ADR-051) — public surface.
 *
 * The dashboard mints a scan, then `startScan` DIRECTLY launches one execution of
 * the pre-created Cloud Run Job (`getConfig().scanJobName`) with per-run env
 * overrides — no Temporal. `cancelScan` cancels that execution (= kill switch).
 * All clients are lazy: importing this module performs no I/O and needs no live
 * GCP credentials.
 *
 * NOTE: the Temporal `scanWorkflow`/activities exports below are retained for the
 * worker fleet but are no longer used by the dashboard's launch path.
 */

export {
  cancelExecution,
  deleteScanJob,
  type JobLaunch,
  launchScanExecution,
  type RunScanJobArgs,
  runScanJob,
  waitForExecution,
} from './cloud-run-jobs.js';
export {
  buildRunOverrides,
  buildScanJob,
  type JobEnvVar,
  jobName,
  jobParent,
  resolveRunServiceAccount,
  SCAN_CONTAINER_NAME,
} from './job-spec.js';
export { runScanJobActivity } from './scan-activities.js';
export { cancelScan, scanJobId, startScan } from './scan-orchestrator.js';
export type { ScanJobActivityInput, ScanWorkflowInput } from './scan-types.js';
export { scanWorkflow, type ScanWorkflowResult } from './scan-workflow.js';
