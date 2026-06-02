/**
 * Kill switch + blast-radius caps (LAUNCH-SPEC §5.6, §3.3; ADR-019 / ADR-051).
 *
 * The kill switch is Temporal workflow cancellation: cancelling the scan's
 * workflow tears down its Cloud Run Job execution. This module wraps
 * `orchestration.cancelScan` with (1) audit emission and (2) per-run teardown
 * hooks, and adds a blast-radius monitor that AUTO-TRIPS the kill switch when a
 * run exceeds its caps (request count, network errors, runtime) — so a runaway
 * agent stops itself even without an operator click.
 */

import type { Scan } from '../domain/types.js';
import { cancelScan } from '../orchestration/index.js';
import { getAuditTee } from './audit.js';

/** Reason a run was killed (for audit + teardown messaging). */
export type KillReason = 'operator' | 'blast_radius' | 'roe_violation' | 'egress_violation' | 'timeout';

/** Per-run blast-radius caps. A breach trips the kill switch automatically. */
export interface BlastRadiusCaps {
  /** Max total outbound requests for the run. */
  readonly maxRequests: number;
  /** Max guardrail denials (RoE/egress) before the run is killed. */
  readonly maxDenials: number;
  /** Max wall-clock seconds for the run (independent of Cloud Run's own cap). */
  readonly maxRuntimeSeconds: number;
}

export const DEFAULT_BLAST_RADIUS_CAPS: BlastRadiusCaps = {
  maxRequests: 50_000,
  maxDenials: 100,
  maxRuntimeSeconds: 3600,
};

/** A teardown hook run during kill (close sessions, delete tmp, flush logs). */
export type TeardownHook = () => Promise<void> | void;

/**
 * Cancel a scan (the kill switch). Runs teardown hooks first (best-effort, never
 * blocking the cancel), cancels the Temporal workflow, then audits the action.
 */
export async function killScan(
  scan: Scan,
  opts: { reason: KillReason; tenantId: string; actor?: string; teardown?: readonly TeardownHook[] } ,
): Promise<void> {
  for (const hook of opts.teardown ?? []) {
    try {
      await hook();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[kill-switch] teardown hook failed:', err);
    }
  }

  await cancelScan(scan);

  await getAuditTee().emit({
    type: 'kill_switch.triggered',
    outcome: 'deny',
    tenantId: opts.tenantId,
    scanId: scan.id,
    ...(opts.actor !== undefined ? { actor: opts.actor } : {}),
    message: `kill switch triggered for scan ${scan.id} (reason=${opts.reason})`,
    detail: { reason: opts.reason, workflowId: scan.temporalWorkflowId },
  });
}

export interface BlastRadiusBreach {
  readonly metric: 'requests' | 'denials' | 'runtime';
  readonly value: number;
  readonly cap: number;
}

/**
 * Per-run blast-radius monitor. The worker calls `recordRequest()` /
 * `recordDenial()` as it works; `check()` returns a breach (or null). When a
 * breach is detected the caller invokes `killScan` with reason `blast_radius`.
 * In-process per run — one Cloud Run Job per scan makes this exactly per-run.
 */
export class BlastRadiusMonitor {
  private requests = 0;
  private denials = 0;
  private readonly startedAt = Date.now();

  constructor(private readonly caps: BlastRadiusCaps = DEFAULT_BLAST_RADIUS_CAPS) {}

  recordRequest(): void {
    this.requests += 1;
  }

  recordDenial(): void {
    this.denials += 1;
  }

  runtimeSeconds(): number {
    return (Date.now() - this.startedAt) / 1000;
  }

  /** Return the first cap breached, or null if the run is within bounds. */
  check(): BlastRadiusBreach | null {
    if (this.requests > this.caps.maxRequests) {
      return { metric: 'requests', value: this.requests, cap: this.caps.maxRequests };
    }
    if (this.denials > this.caps.maxDenials) {
      return { metric: 'denials', value: this.denials, cap: this.caps.maxDenials };
    }
    const runtime = this.runtimeSeconds();
    if (runtime > this.caps.maxRuntimeSeconds) {
      return { metric: 'runtime', value: Math.round(runtime), cap: this.caps.maxRuntimeSeconds };
    }
    return null;
  }

  /** Record + check in one step (the hot-path call site for the engine). */
  recordRequestAndCheck(): BlastRadiusBreach | null {
    this.recordRequest();
    return this.check();
  }

  snapshot(): { requests: number; denials: number; runtimeSeconds: number } {
    return { requests: this.requests, denials: this.denials, runtimeSeconds: Math.round(this.runtimeSeconds()) };
  }
}
