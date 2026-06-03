/**
 * Scan orchestrator (ADR-051) — the control-plane entry the dashboard calls.
 *
 * `startScan` builds the per-run job env and DIRECTLY launches one execution of
 * the pre-created Cloud Run Job (`getConfig().scanJobName`) with env overrides —
 * no Temporal, no per-scan Job resource. The worker reads the overrides, runs the
 * scan, and POSTs findings back to `SHOR_FINDINGS_SINK_URL` with the shared
 * `SHOR_SINK_TOKEN`. The started execution's resource name is recorded on the
 * scan (via `scanRepo.setWorkflowId`) so `cancelScan` can cancel it — the kill
 * switch. Clients are lazy; importing this needs no live GCP credentials.
 */

import { getConfig } from '../config.js';
import { gsUri } from '../cloud/storage.js';
import { scanRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, Scan } from '../domain/types.js';
import type { Roe, RoeHostRule } from '../guardrails/roe.js';
import type { InjectionManifest } from '../secrets/injection.js';
import { cancelExecution, launchScanExecution } from './cloud-run-jobs.js';
import type { JobEnvVar } from './job-spec.js';

/** Per-scan Cloud Run Job id derived from the scan id (`shor-scan-<scanId>`). */
export function scanJobId(scanId: string): string {
  return `shor-scan-${scanId}`;
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
  codebaseVersion: CodebaseVersion | null,
  manifest: InjectionManifest,
): Promise<Scan> {
  const cfg = getConfig();

  // Per-run env applied as the run-time override on the worker Job execution.
  const runEnv: JobEnvVar[] = [
    { name: 'SHOR_SCAN_ID', value: scan.id },
    { name: 'SHOR_TARGET_URL', value: project.targetUrl },
    { name: 'SHOR_ROE', value: JSON.stringify(buildRoe(project.targetUrl)) },
    { name: 'SHOR_REPO_PATH', value: REPO_PATH },
    { name: 'SHOR_FINDINGS_SINK_URL', value: cfg.publicUrl },
    { name: 'SHOR_SINK_TOKEN', value: cfg.sinkToken },
  ];

  // White-box only: point the worker at the staged repo. Use the version's
  // STORED staging prefix — ingest stages the source under a freshly-minted UUID
  // kept in `gcsPrefix`, which is NOT the DB row `id`. Black-box scans
  // (codebaseVersion === null) omit this so the worker materializes no code.
  if (codebaseVersion) {
    runEnv.push({ name: 'SHOR_REPO_GCS_URI', value: gsUri(codebaseVersion.gcsPrefix) });
  }

  // When Sinas-mode is configured, forward the connection to the worker so the
  // reporting step offloads finalization to the user's Sinas instance.
  if (process.env.SINAS_ENABLED === '1') {
    runEnv.push(
      { name: 'SINAS_ENABLED', value: '1' },
      { name: 'SINAS_URL', value: process.env.SINAS_URL ?? '' },
      { name: 'SINAS_API_KEY', value: process.env.SINAS_API_KEY ?? '' },
      { name: 'SINAS_NAMESPACE', value: process.env.SINAS_NAMESPACE ?? 'pentest' },
    );
  }

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
