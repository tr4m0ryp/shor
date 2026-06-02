/**
 * Scan orchestrator (ADR-051) — the control-plane entry the dashboard calls.
 *
 * `startScan` builds the per-run job env and DIRECTLY launches one execution of
 * the pre-created Cloud Run Job (`getConfig().scanJobName`) with env overrides —
 * no Temporal, no per-scan Job resource. The worker reads the overrides, runs the
 * scan, and POSTs findings back to `AEGIS_FINDINGS_SINK_URL` with the shared
 * `AEGIS_SINK_TOKEN`. The started execution's resource name is recorded on the
 * scan (via `scanRepo.setWorkflowId`) so `cancelScan` can cancel it — the kill
 * switch. Clients are lazy; importing this needs no live GCP credentials.
 */

import { getConfig } from '../config.js';
import { gsUri, objectPrefix } from '../cloud/storage.js';
import { scanRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, Scan } from '../domain/types.js';
import type { Roe, RoeHostRule } from '../guardrails/roe.js';
import type { InjectionManifest } from '../secrets/injection.js';
import { cancelExecution, launchScanExecution } from './cloud-run-jobs.js';
import type { JobEnvVar } from './job-spec.js';

/** Per-scan Cloud Run Job id derived from the scan id (`aegis-scan-<scanId>`). */
export function scanJobId(scanId: string): string {
  return `aegis-scan-${scanId}`;
}

/** Container path the staged repo is mounted/expanded at inside the worker. */
const REPO_PATH = '/work/repo';

/**
 * Build the default-deny Rules of Engagement for a scan from the project's
 * target URL: the target's host (and its port, when non-default) is the only
 * in-scope host. The worker re-validates and re-checks this on every action.
 */
function buildRoe(targetUrl: string): Roe {
  const url = new URL(targetUrl);
  const scheme = url.protocol === 'http:' ? 'http' : 'https';
  const rule: RoeHostRule = {
    host: url.hostname.toLowerCase(),
    schemes: [scheme],
    ...(url.port ? { ports: [Number.parseInt(url.port, 10)] } : {}),
  };
  return { version: 1, targetUrl, allowedHosts: [rule] };
}

/**
 * Start a scan: build the per-run env, launch one execution of the pre-created
 * Cloud Run Job, mark the scan `running`, and persist the execution name (stored
 * via `setWorkflowId`). Returns the running scan with its execution recorded (or
 * the original scan if the persist races a delete).
 */
export async function startScan(
  scan: Scan,
  project: Project,
  codebaseVersion: CodebaseVersion,
  manifest: InjectionManifest,
): Promise<Scan> {
  const cfg = getConfig();

  const repoGcsUri = gsUri(
    objectPrefix(manifest.tenantId, project.id, codebaseVersion.id),
  );

  // Per-run env applied as the run-time override on the worker Job execution.
  const runEnv: JobEnvVar[] = [
    { name: 'AEGIS_SCAN_ID', value: scan.id },
    { name: 'AEGIS_TARGET_URL', value: project.targetUrl },
    { name: 'AEGIS_REPO_GCS_URI', value: repoGcsUri },
    { name: 'AEGIS_ROE', value: JSON.stringify(buildRoe(project.targetUrl)) },
    { name: 'AEGIS_REPO_PATH', value: REPO_PATH },
    { name: 'AEGIS_FINDINGS_SINK_URL', value: cfg.publicUrl },
    { name: 'AEGIS_SINK_TOKEN', value: cfg.sinkToken },
  ];

  const launch = await launchScanExecution(cfg.scanJobName, runEnv);

  await scanRepo.setStatus(manifest.tenantId, scan.id, 'running');
  const executionName = launch.executionName ?? '';
  const updated = executionName
    ? await scanRepo.setWorkflowId(manifest.tenantId, scan.id, executionName)
    : null;
  return updated ?? { ...scan, status: 'running', temporalWorkflowId: executionName || null };
}

/**
 * Cancel a scan: cancel its running Cloud Run Job execution (the kill switch).
 * The execution resource name was recorded on the scan at launch. No-op when the
 * scan has no recorded execution.
 */
export async function cancelScan(scan: Scan): Promise<void> {
  const executionName = scan.temporalWorkflowId;
  if (!executionName) return;
  await cancelExecution(executionName);
}
