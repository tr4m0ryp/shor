/**
 * Temporal activities backing `scanWorkflow` (ADR-051).
 *
 * The single load-bearing activity launches the per-scan Cloud Run Job and waits
 * for the execution to finish. Cancellation (the kill switch) deletes the Job
 * execution. These run on the persistent worker fleet — NOT in the scan
 * container — so they may touch GCP. Kept import-safe: GCP clients are lazy.
 */

import { Context } from '@temporalio/activity';
import {
  cancelExecution,
  deleteScanJob,
  runScanJob,
  waitForExecution,
} from './cloud-run-jobs.js';
import type { JobEnvVar } from './job-spec.js';
import type { ScanJobActivityInput } from './scan-types.js';

/**
 * Launch the scan's Cloud Run Job and wait for it to complete.
 *
 * Heartbeats the started execution name so a cancellation can reach it even mid-
 * wait. On Temporal cancellation, deletes the Job execution (kill switch) and
 * re-throws so the workflow records the cancelled state.
 */
export async function runScanJobActivity(input: ScanJobActivityInput): Promise<void> {
  const baseEnv: JobEnvVar[] = [...input.baseEnv];
  const runEnv: JobEnvVar[] = [...input.runEnv];

  const launch = await runScanJob({
    jobId: input.jobId,
    manifest: input.manifest,
    baseEnv,
    runEnv,
  });

  // Surface the execution name so the cancel path (and operators) can target it.
  Context.current().heartbeat({ executionName: launch.executionName, jobName: launch.jobName });

  try {
    if (launch.executionName) {
      await waitForExecution(launch.executionName);
    }
  } catch (err) {
    // On cancellation, Temporal raises a CancelledFailure out of heartbeat()/
    // the cancellation scope — kill the run, then propagate.
    if (Context.current().cancellationSignal.aborted) {
      await killRun(input.jobId, launch.executionName);
    }
    throw err;
  }
}

/** Kill switch helper: cancel the execution then delete the per-scan Job. */
async function killRun(jobId: string, executionName: string | null): Promise<void> {
  if (executionName) {
    await cancelExecution(executionName).catch(() => undefined);
  }
  await deleteScanJob(jobId).catch(() => undefined);
}
