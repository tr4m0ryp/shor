/**
 * Shared, side-effect-free types for the scan workflow + its activity (ADR-051).
 *
 * Imported by the Temporal workflow (which runs in the deterministic sandbox)
 * AND by the activity, so this module must construct NOTHING and import no GCP
 * or Temporal-runtime side effects.
 */

import type { InjectionManifest } from '../secrets/injection.js';
import type { JobEnvVar } from './job-spec.js';

/** Input to `scanWorkflow` and `runScanJobActivity`. Fully serializable. */
export interface ScanJobActivityInput {
  /** Stable per-scan Cloud Run Job id (`aegis-scan-<scanId>`). */
  readonly jobId: string;
  /** Per-run secret mount + scoped identity binding for the Job resource. */
  readonly manifest: InjectionManifest;
  /** Baseline container env baked into the Job resource. */
  readonly baseEnv: readonly JobEnvVar[];
  /** Per-run env applied as a run-time override (scan id, target URL, repo URI). */
  readonly runEnv: readonly JobEnvVar[];
}

/** Workflow input — the scan id plus everything the activity needs. */
export interface ScanWorkflowInput extends ScanJobActivityInput {
  /** Domain scan id (for correlation/logging). */
  readonly scanId: string;
}
