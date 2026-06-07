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
import { PIPELINE_PLAN, SKILL_CATEGORY, type SkillCategory, TOTAL_AGENTS } from './taxonomy.js';

/** Per-agent render status (mirrors storron's pending pill states). */
export type StepStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';

export interface AgentView {
  readonly name: string;
  readonly label: string;
  readonly status: StepStatus;
  readonly durationMs: number | null;
  /** Epoch-ms start/end for the timeline (finishedAt null while running). */
  readonly startedAt: number | null;
  readonly finishedAt: number | null;
  /** Named sub-tasks the agent runs internally (static plan; drill-down). */
  readonly subtasks: readonly string[];
  /** Skills the agent has actually used so far (live). */
  readonly skills: readonly string[];
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
  /** Names of agents running concurrently right now (for the banner). */
  readonly runningAgents: readonly string[];
  readonly completed: number;
  readonly total: number;
  readonly percent: number;
  readonly updatedAt: string | null;
  /** Timeline axis bounds (epoch ms) across all agents that have a start. */
  readonly runStart: number | null;
  readonly runEnd: number | null;
  /** Distinct offensive tools that fired this run + who used them (arsenal grid). */
  readonly arsenal: readonly ArsenalEntry[];
  readonly phases: readonly PhaseView[];
}

export interface ArsenalEntry {
  readonly skill: string;
  readonly category: SkillCategory;
  readonly agents: readonly string[];
}

/** Phase rollup precedence: a worse child status wins (storron's order). */
const PHASE_PRECEDENCE: readonly StepStatus[] = ['failed', 'in_progress', 'pending', 'completed', 'skipped'];

function rollup(children: readonly StepStatus[]): StepStatus {
  for (const s of PHASE_PRECEDENCE) {
    if (children.includes(s)) return s;
  }
  return 'pending';
}

interface AgentTiming {
  status: StepStatus;
  durationMs: number | null;
  startedAt: number | null;
  finishedAt: number | null;
}

function agentStatus(name: string, progress: ScanProgress, scanClosed: boolean): AgentTiming {
  const started = progress.starts?.[name] ?? null;
  const done = progress.completedAgents.find((a) => a.agent === name);
  if (done) {
    return {
      status: done.status,
      durationMs: done.durationMs,
      startedAt: done.startedAt ?? started,
      finishedAt: done.finishedAt ?? null,
    };
  }
  if (progress.failedAgent === name) return { status: 'failed', durationMs: null, startedAt: started, finishedAt: null };
  // Concurrency: any agent in the running set is in progress (currentAgent is
  // just one representative for the banner).
  const running = progress.runningAgents ?? (progress.currentAgent ? [progress.currentAgent] : []);
  // A closed/archived scan can't have a live agent: a worker that died mid-run
  // leaves a stale "running" entry in the last snapshot, so never show in_progress
  // once the scan is terminal — fall through to skipped.
  if (!scanClosed && running.includes(name)) {
    return { status: 'in_progress', durationMs: null, startedAt: started, finishedAt: null };
  }
  // A closed scan that never reached this agent skipped it; otherwise it is queued.
  return { status: scanClosed ? 'skipped' : 'pending', durationMs: null, startedAt: null, finishedAt: null };
}

/**
 * Build the full progress view for a scan. When the worker has not posted a
 * snapshot yet, every agent shows `pending` (or `skipped` if the scan is
 * already closed) so the feed still renders the plan.
 */
export function deriveProgressView(scan: Scan): ProgressView {
  const scanClosed =
    scan.status === 'completed' ||
    scan.status === 'failed' ||
    scan.status === 'cancelled' ||
    scan.status === 'archived';
  const progress: ScanProgress = scan.progress ?? {
    status: scan.status,
    currentPhase: null,
    currentAgent: null,
    failedAgent: null,
    completedAgents: [],
    updatedAt: scan.finishedAt ?? scan.startedAt ?? '',
  };

  const skillsByAgent = progress.skills ?? {};
  let completed = 0;
  let runStart: number | null = null;
  let runEnd: number | null = null;
  const phases: PhaseView[] = PIPELINE_PLAN.map((phase) => {
    const agents: AgentView[] = phase.agents.map((a) => {
      const t = agentStatus(a.name, progress, scanClosed);
      if (t.status === 'completed') completed += 1;
      if (t.startedAt != null) runStart = runStart == null ? t.startedAt : Math.min(runStart, t.startedAt);
      if (t.finishedAt != null) runEnd = runEnd == null ? t.finishedAt : Math.max(runEnd, t.finishedAt);
      return {
        name: a.name,
        label: a.label,
        status: t.status,
        durationMs: t.durationMs,
        startedAt: t.startedAt,
        finishedAt: t.finishedAt,
        subtasks: a.subtasks ?? [],
        skills: skillsByAgent[a.name] ?? [],
      };
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

  // A completed scan reads 100% even if some agents were skipped/failed — the
  // run is done. failed/cancelled keep the real percent (shows where it stopped).
  const percent =
    scan.status === 'completed'
      ? 100
      : TOTAL_AGENTS === 0
        ? 0
        : Math.round((completed / TOTAL_AGENTS) * 100);
  const runningAgents = progress.runningAgents ?? (progress.currentAgent ? [progress.currentAgent] : []);
  // Running agents have no finish yet — extend the axis to "now" so their bars render.
  if (runningAgents.length > 0 && runStart != null) runEnd = Math.max(runEnd ?? runStart, Date.now());

  // Tool arsenal: distinct skills that fired + which agents (by label) used each.
  const labelOf = new Map<string, string>();
  for (const ph of PIPELINE_PLAN) for (const a of ph.agents) labelOf.set(a.name, a.label);
  const arsenalMap = new Map<string, Set<string>>();
  for (const [agentName, list] of Object.entries(skillsByAgent)) {
    for (const skill of list) {
      if (!arsenalMap.has(skill)) arsenalMap.set(skill, new Set());
      arsenalMap.get(skill)?.add(labelOf.get(agentName) ?? agentName);
    }
  }
  const arsenal: ArsenalEntry[] = [...arsenalMap.entries()]
    .map(([skill, agents]) => ({ skill, category: SKILL_CATEGORY[skill] ?? ('exploit' as SkillCategory), agents: [...agents] }))
    .sort((a, b) => a.category.localeCompare(b.category) || a.skill.localeCompare(b.skill));

  return {
    status: scan.status,
    currentPhase: progress.currentPhase,
    currentAgent: progress.currentAgent,
    runningAgents,
    completed,
    total: TOTAL_AGENTS,
    percent,
    updatedAt: progress.updatedAt || null,
    runStart,
    runEnd,
    arsenal,
    phases,
  };
}
