/**
 * Scan orchestrator (ADR-051) — the control-plane entry the dashboard calls.
 *
 * `startScan` builds the per-run job env, starts `scanWorkflow` on Temporal
 * Cloud (per-scan workflow id + task queue), and records the workflow id on the
 * scan. `cancelScan` cancels the workflow — which kills the Cloud Run Job
 * execution (the kill switch). This module never touches GCP directly; the Job
 * launch happens inside the workflow's activity on the worker fleet.
 */

import { getTemporalClient, scanTaskQueue, scanWorkflowId } from '../cloud/temporal.js';
import { gsUri, objectPrefix } from '../cloud/storage.js';
import { scanRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, Scan } from '../domain/types.js';
import { PROVIDER_KEY_FILE_ENV } from '../secrets/injection.js';
import type { InjectionManifest } from '../secrets/injection.js';
import type { JobEnvVar } from './job-spec.js';
import type { ScanWorkflowInput } from './scan-types.js';
import { scanWorkflow } from './scan-workflow.js';

/** Per-scan Cloud Run Job id derived from the scan id (`aegis-scan-<scanId>`). */
export function scanJobId(scanId: string): string {
  return `aegis-scan-${scanId}`;
}

/**
 * Start a scan: build job env, launch `scanWorkflow` on Temporal Cloud, and
 * persist the workflow id. Returns the started scan with `temporalWorkflowId`
 * set (or the original scan if the persist races a delete).
 */
export async function startScan(
  scan: Scan,
  project: Project,
  codebaseVersion: CodebaseVersion,
  manifest: InjectionManifest,
): Promise<Scan> {
  const jobId = scanJobId(scan.id);
  const workflowId = scanWorkflowId(scan.id);

  const repoGcsUri = gsUri(
    objectPrefix(manifest.tenantId, project.id, codebaseVersion.id),
  );

  // Baseline env baked into the Job resource: the engine reads the file-mounted
  // provider key via AEGIS_PROVIDER_KEY_FILE (a path, never the material).
  const baseEnv: JobEnvVar[] = [
    { name: PROVIDER_KEY_FILE_ENV, value: manifest.providerKeyMount.mountPath },
    { name: 'AEGIS_PROVIDER', value: manifest.provider },
    { name: 'AEGIS_TENANT_ID', value: manifest.tenantId },
  ];

  // Per-run env applied as the run-time override.
  const runEnv: JobEnvVar[] = [
    { name: 'AEGIS_SCAN_ID', value: scan.id },
    { name: 'AEGIS_PROJECT_ID', value: project.id },
    { name: 'AEGIS_CODEBASE_VERSION_ID', value: codebaseVersion.id },
    { name: 'AEGIS_TARGET_URL', value: project.targetUrl },
    { name: 'AEGIS_REPO_GCS_URI', value: repoGcsUri },
  ];

  const input: ScanWorkflowInput = {
    scanId: scan.id,
    jobId,
    manifest,
    baseEnv,
    runEnv,
  };

  const client = await getTemporalClient();
  await client.workflow.start(scanWorkflow, {
    taskQueue: scanTaskQueue(),
    workflowId,
    args: [input],
  });

  const updated = await scanRepo.setWorkflowId(manifest.tenantId, scan.id, workflowId);
  return updated ?? { ...scan, temporalWorkflowId: workflowId };
}

/**
 * Cancel a scan: cancel its Temporal workflow (the kill switch). The workflow's
 * activity deletes the Cloud Run Job execution on cancellation. No-op when the
 * scan has no recorded workflow id.
 */
export async function cancelScan(scan: Scan): Promise<void> {
  const workflowId = scan.temporalWorkflowId ?? scanWorkflowId(scan.id);
  const client = await getTemporalClient();
  const handle = client.workflow.getHandle(workflowId);
  await handle.cancel();
}
