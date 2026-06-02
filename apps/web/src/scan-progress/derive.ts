/**
 * Derive the rendered progress view from a scan + its worker snapshot.
 *
 * The worker pushes a flat snapshot (current phase/agent, failed agent, and a
 * list of completed-agent records). This blends it with the static
 * {@link PIPELINE_PLAN} to produce per-agent and per-phase statuses the
 * activity tab renders directly — the same poll-derive-render model storron
 * uses (no event stream needed).
 */

import type { Scan, ScanProgress } from '../domain/types.js';
import { PIPELINE_PLAN, TOTAL_AGENTS } from './taxonomy.js';

/** Per-agent render status (mirrors storron's pending pill states). */
export type StepStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';

export interface AgentView {
  readonly name: string;
  readonly label: string;
  readonly status: StepStatus;
  readonly durationMs: number | null;
}

export interface PhaseView {
  readonly id: string;
  readonly label: string;
  readonly status: StepStatus;
  readonly done: number;
  readonly total: number;
  readonly agents: readonly AgentView[];
}

export interface ProgressView {
  readonly status: Scan['status'];
  readonly currentPhase: string | null;
  readonly currentAgent: string | null;
  readonly completed: number;
  readonly total: number;
  readonly percent: number;
  readonly updatedAt: string | null;
  readonly phases: readonly PhaseView[];
}

/** Phase rollup precedence: a worse child status wins (storron's order). */
const PHASE_PRECEDENCE: readonly StepStatus[] = ['failed', 'in_progress', 'pending', 'completed', 'skipped'];

function rollup(children: readonly StepStatus[]): StepStatus {
  for (const s of PHASE_PRECEDENCE) {
    if (children.includes(s)) return s;
  }
  return 'pending';
}

function agentStatus(
  name: string,
  progress: ScanProgress,
  scanClosed: boolean,
): { status: StepStatus; durationMs: number | null } {
  const done = progress.completedAgents.find((a) => a.agent === name);
  if (progress.failedAgent === name) return { status: 'failed', durationMs: done?.durationMs ?? null };
  if (done) return { status: done.status, durationMs: done.durationMs };
  if (progress.currentAgent === name) return { status: 'in_progress', durationMs: null };
  // A closed scan that never reached this agent skipped it; otherwise it is queued.
  return { status: scanClosed ? 'skipped' : 'pending', durationMs: null };
}

/**
 * Build the full progress view for a scan. When the worker has not posted a
 * snapshot yet, every agent shows `pending` (or `skipped` if the scan is
 * already closed) so the feed still renders the plan.
 */
export function deriveProgressView(scan: Scan): ProgressView {
  const scanClosed = scan.status === 'completed' || scan.status === 'failed' || scan.status === 'cancelled';
  const progress: ScanProgress = scan.progress ?? {
    status: scan.status,
    currentPhase: null,
    currentAgent: null,
    failedAgent: null,
    completedAgents: [],
    updatedAt: scan.finishedAt ?? scan.startedAt ?? '',
  };

  let completed = 0;
  const phases: PhaseView[] = PIPELINE_PLAN.map((phase) => {
    const agents: AgentView[] = phase.agents.map((a) => {
      const { status, durationMs } = agentStatus(a.name, progress, scanClosed);
      if (status === 'completed') completed += 1;
      return { name: a.name, label: a.label, status, durationMs };
    });
    const done = agents.filter((a) => a.status === 'completed').length;
    return {
      id: phase.id,
      label: phase.label,
      status: rollup(agents.map((a) => a.status)),
      done,
      total: agents.length,
      agents,
    };
  });

  const percent = TOTAL_AGENTS === 0 ? 0 : Math.round((completed / TOTAL_AGENTS) * 100);
  return {
    status: scan.status,
    currentPhase: progress.currentPhase,
    currentAgent: progress.currentAgent,
    completed,
    total: TOTAL_AGENTS,
    percent,
    updatedAt: progress.updatedAt || null,
    phases,
  };
}
