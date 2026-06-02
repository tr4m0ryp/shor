/**
 * Scan orchestration (ADR-051) — public surface.
 *
 * The dashboard mints a scan, `startScan` launches a Temporal Cloud workflow,
 * whose single activity runs a per-scan Cloud Run Job. `cancelScan` cancels the
 * workflow (= kill switch). All clients are lazy: importing this module performs
 * no I/O and needs no live GCP/Temporal credentials.
 *
 * NOTE: the worker fleet registers `scanWorkflow` (workflow) + the activities
 * from `./scan-activities.js`; the dashboard only uses the orchestrator.
 */

export {
  cancelExecution,
  deleteScanJob,
  type JobLaunch,
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
