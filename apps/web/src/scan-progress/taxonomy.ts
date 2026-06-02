/**
 * Phase + agent taxonomy for the live run-progress feed (ADR-051).
 *
 * Mirrors the worker's pipeline (`apps/worker/src/types/agents.ts` order and
 * `session-manager/phase-map.ts` grouping) but with the dashboard's
 * remediation-oriented vocabulary: the engine runs attack agents, the product
 * surfaces the result as fixes, so the labels read as analysis/remediation
 * rather than "exploit". The read route blends a worker snapshot with this
 * static plan to render phase cards, so order + names must stay in lockstep
 * with the worker.
 */

/** A single agent within a phase, in run order. */
export interface AgentSpec {
  readonly name: string;
  readonly label: string;
}

/** A pipeline phase: a titled group of agents the feed renders as one card. */
export interface PhaseSpec {
  readonly id: string;
  readonly label: string;
  readonly agents: readonly AgentSpec[];
}

/**
 * The pipeline plan, in execution order. The flat agent order here MUST match
 * the worker's `ALL_AGENTS` so completed-agent records line up by name.
 */
export const PIPELINE_PLAN: readonly PhaseSpec[] = [
  { id: 'pre-recon', label: 'Reconnaissance', agents: [{ name: 'pre-recon', label: 'Pre-recon' }] },
  { id: 'recon', label: 'Mapping', agents: [{ name: 'recon', label: 'Recon' }] },
  {
    id: 'vulnerability-analysis',
    label: 'Vulnerability Analysis',
    agents: [
      { name: 'injection-vuln', label: 'Injection' },
      { name: 'xss-vuln', label: 'XSS' },
      { name: 'auth-vuln', label: 'Auth' },
      { name: 'ssrf-vuln', label: 'SSRF' },
      { name: 'authz-vuln', label: 'Authz' },
    ],
  },
  {
    id: 'exploitation',
    label: 'Validation',
    agents: [
      { name: 'injection-exploit', label: 'Injection' },
      { name: 'xss-exploit', label: 'XSS' },
      { name: 'auth-exploit', label: 'Auth' },
      { name: 'ssrf-exploit', label: 'SSRF' },
      { name: 'authz-exploit', label: 'Authz' },
    ],
  },
  { id: 'reporting', label: 'Remediation Report', agents: [{ name: 'report', label: 'Report' }] },
  {
    id: 'attack-surface',
    label: 'Attack Surface & Fixes',
    agents: [{ name: 'attack-surface', label: 'Attack Surface' }],
  },
];

/** Total agent count across all phases — the denominator for percent-complete. */
export const TOTAL_AGENTS: number = PIPELINE_PLAN.reduce((n, p) => n + p.agents.length, 0);
