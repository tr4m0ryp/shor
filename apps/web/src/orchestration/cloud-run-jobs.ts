/**
 * Cloud Run Admin API (v2) wrapper for the Job-per-scan sandbox (ADR-018 / ADR-051).
 *
 * Each scan gets its OWN Cloud Run Job, created with the per-run service identity
 * and the scoped Secret Manager volume mount (mandatory — see `job-spec.ts`),
 * then executed with per-run env overrides. The activity launches the execution
 * and waits; cancellation deletes the Job (which cancels its running execution
 * and tears the per-run resource down — the kill switch).
 *
 * Lazy clients: the `JobsClient`/`ExecutionsClient` are constructed on first use,
 * never at import time, so `tsc`/`build` need no live GCP credentials.
 */

import type { ExecutionsClient, JobsClient } from '@google-cloud/run';
import { getConfig } from '../config.js';
import type { InjectionManifest } from '../secrets/injection.js';
import {
  buildRunOverrides,
  buildScanJob,
  type JobEnvVar,
  jobName,
  jobParent,
} from './job-spec.js';

let jobsClient: JobsClient | undefined;
let executionsClient: ExecutionsClient | undefined;

async function getJobsClient(): Promise<JobsClient> {
  if (!jobsClient) {
    const mod = await import('@google-cloud/run');
    jobsClient = new mod.JobsClient();
  }
  return jobsClient;
}

async function getExecutionsClient(): Promise<ExecutionsClient> {
  if (!executionsClient) {
    const mod = await import('@google-cloud/run');
    executionsClient = new mod.ExecutionsClient();
  }
  return executionsClient;
}

/** Outcome of launching a scan Job execution. */
export interface JobLaunch {
  /** Resource name of the created Job `…/jobs/<jobId>`. */
  readonly jobName: string;
  /** Resource name of the started execution `…/executions/<exec>`, when known. */
  readonly executionName: string | null;
}

/**
 * Launch ONE execution of a pre-created Cloud Run Job (named by `scanJobName`)
 * with per-run env overrides — the direct-launch path the dashboard uses
 * (ADR-051). Unlike `runScanJob`, this creates NO per-scan Job resource: a
 * single worker Job already exists and every scan runs as an execution of it.
 * Returns the Job + execution resource names so the caller has a cancel handle.
 */
export async function launchScanExecution(
  jobShortName: string,
  runEnv: readonly JobEnvVar[],
): Promise<JobLaunch> {
  const cfg = getConfig().cloudRun;
  const client = await getJobsClient();
  const name = jobName(cfg, jobShortName);

  const [operation] = await client.runJob({
    name,
    overrides: buildRunOverrides(runEnv) as never,
  });
  const executionName = executionNameFromMetadata(operation);
  return { jobName: name, executionName };
}

export interface RunScanJobArgs {
  /** Stable per-scan Job id (`shor-scan-<scanId>`); names the Job resource. */
  readonly jobId: string;
  /** Per-run secret mount + scoped identity binding. */
  readonly manifest: InjectionManifest;
  /** Baseline container env baked into the Job resource. */
  readonly baseEnv: readonly JobEnvVar[];
  /** Per-run env applied as a run-time override (scan id, target, repo URI). */
  readonly runEnv: readonly JobEnvVar[];
}

/**
 * Create (idempotently) the per-scan Job, then start one execution with the
 * per-run env override. Returns the Job + execution names; the execution name is
 * resolved from the operation metadata so the caller has a cancel handle BEFORE
 * waiting for completion.
 */
export async function runScanJob(args: RunScanJobArgs): Promise<JobLaunch> {
  const cfg = getConfig().cloudRun;
  const client = await getJobsClient();
  const name = jobName(cfg, args.jobId);

  await ensureJob(client, cfg, args);

  const [operation] = await client.runJob({
    name,
    overrides: buildRunOverrides(args.runEnv) as never,
  });
  const executionName = executionNameFromMetadata(operation);
  return { jobName: name, executionName };
}

/** Default poll interval while waiting for an execution to reach a terminal state. */
const WAIT_POLL_MS = 15_000;

/**
 * Poll the execution until it reaches a terminal state. Resolves on success;
 * throws when the execution ends with failures or is cancelled, so the activity
 * layer (and thus the workflow) surfaces the failure. Polling — rather than
 * holding the `runJob` LRO — keeps a cancel handle live and survives the
 * activity being retried.
 */
export async function waitForExecution(executionName: string, pollMs = WAIT_POLL_MS): Promise<void> {
  if (!executionName) throw new Error('waitForExecution: missing execution name');
  const client = await getExecutionsClient();
  for (;;) {
    const [execution] = await client.getExecution({ name: executionName });
    const failed = execution.failedCount ?? 0;
    const cancelled = execution.cancelledCount ?? 0;
    const succeeded = execution.succeededCount ?? 0;
    const completed = execution.completionTime != null;

    if (completed || failed > 0 || cancelled > 0) {
      if (failed > 0) throw new Error(`scan execution failed (${failed} task(s) failed): ${executionName}`);
      if (cancelled > 0) throw new Error(`scan execution cancelled: ${executionName}`);
      if (succeeded > 0 || completed) return;
    }
    await sleep(pollMs);
  }
}

/**
 * Kill switch: cancel a running execution. Best-effort — a missing/finished
 * execution is not an error.
 */
export async function cancelExecution(executionName: string): Promise<void> {
  if (!executionName) return;
  const client = await getExecutionsClient();
  try {
    const [operation] = await client.cancelExecution({ name: executionName });
    await operation.promise();
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
}

/**
 * Delete the per-scan Job (and thereby its executions) — full teardown of the
 * per-run resource. Best-effort: a missing Job is not an error.
 */
export async function deleteScanJob(jobId: string): Promise<void> {
  const cfg = getConfig().cloudRun;
  const client = await getJobsClient();
  try {
    const [operation] = await client.deleteJob({ name: jobName(cfg, jobId) });
    await operation.promise();
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
}

/** Create the per-scan Job if it does not already exist (re-run safe). */
async function ensureJob(client: JobsClient, cfg: ReturnType<typeof getConfig>['cloudRun'], args: RunScanJobArgs): Promise<void> {
  try {
    await client.getJob({ name: jobName(cfg, args.jobId) });
    return; // already exists — re-run reuses it
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
  const [operation] = await client.createJob({
    parent: jobParent(cfg),
    jobId: args.jobId,
    job: buildScanJob(cfg, args.manifest, args.baseEnv) as never,
  });
  await operation.promise();
}

/** Best-effort extraction of the execution resource name from the LRO metadata. */
function executionNameFromMetadata(operation: unknown): string | null {
  const meta = (operation as { metadata?: unknown } | null)?.metadata;
  if (meta && typeof meta === 'object' && 'name' in meta) {
    const name = (meta as { name?: unknown }).name;
    if (typeof name === 'string') return name;
  }
  return null;
}

/** GRPC NOT_FOUND is code 5; tolerate it for idempotent create/cancel/delete. */
function isNotFound(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'code' in err && (err as { code: unknown }).code === 5;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
