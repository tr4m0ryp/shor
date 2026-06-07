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

/**
 * A single agent within a phase, in run order. `subtasks` are the named
 * sub-agents / method phases the agent's system prompt runs internally — they
 * are not independently tracked at runtime (the agent writes one deliverable),
 * so the drill-down shows them as the agent's plan, sharing the agent's status.
 * Authoritative source: the worker prompt files (`apps/worker/prompts/*.txt`).
 */
export interface AgentSpec {
  readonly name: string;
  readonly label: string;
  readonly subtasks?: readonly string[];
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
// Sub-task method phases the vuln/exploit prompts run internally (shared shape;
// these agents have no named sub-agents, only numbered method sections).
const VULN_SUBTASKS = ['Enumerate sources', 'Analyze sink classes', 'Confirm vectors', 'Write findings queue'];
const SCREEN_SUBTASKS = ['Load hypotheses', 'Independent exploitability check', 'Refutation attempt', 'Write screened queue'];
const EXPLOIT_SUBTASKS = ['Plan attack', 'Probe payloads', 'Bypass defenses', 'Capture evidence'];

export const PIPELINE_PLAN: readonly PhaseSpec[] = [
  {
    id: 'pre-recon',
    label: 'Reconnaissance',
    agents: [
      {
        name: 'pre-recon',
        label: 'Pre-recon',
        // prompts/pre-recon-code.txt:180-200
        subtasks: [
          'Architecture Scanner',
          'Entry Point Mapper',
          'Security Pattern Hunter',
          'XSS / Injection Sink Hunter',
          'SSRF / External Request Tracer',
          'Data Security Auditor',
        ],
      },
    ],
  },
  {
    id: 'recon',
    label: 'Mapping',
    agents: [
      {
        name: 'recon',
        label: 'Recon',
        // prompts/recon.txt:155-161,381
        subtasks: [
          'Route Mapper',
          'Authorization Checker',
          'Input Validator',
          'Session Handler',
          'Authorization Architecture',
          'Injection Source Tracer',
        ],
      },
    ],
  },
  {
    id: 'threat-model',
    label: 'Threat Model',
    agents: [
      {
        name: 'threat-model',
        label: 'Threat Model',
        subtasks: ['Map trust boundaries', 'Enumerate assets and actors', 'Rank abuse cases'],
      },
    ],
  },
  {
    id: 'vulnerability-analysis',
    label: 'Vulnerability Analysis',
    agents: [
      { name: 'injection-vuln', label: '(VA) Injection', subtasks: VULN_SUBTASKS },
      { name: 'xss-vuln', label: '(VA) XSS', subtasks: VULN_SUBTASKS },
      { name: 'auth-vuln', label: '(VA) Auth', subtasks: VULN_SUBTASKS },
      { name: 'ssrf-vuln', label: '(VA) SSRF', subtasks: VULN_SUBTASKS },
      { name: 'authz-vuln', label: '(VA) Authz', subtasks: VULN_SUBTASKS },
      { name: 'logic-vuln', label: '(VA) Logic', subtasks: VULN_SUBTASKS },
      { name: 'misconfig-web-vuln', label: '(VA) Web Misconfig', subtasks: VULN_SUBTASKS },
    ],
  },
  {
    id: 'adversarial-screen',
    label: 'Adversarial Screen',
    agents: [
      { name: 'injection-screen', label: 'Injection', subtasks: SCREEN_SUBTASKS },
      { name: 'xss-screen', label: 'XSS', subtasks: SCREEN_SUBTASKS },
      { name: 'auth-screen', label: 'Auth', subtasks: SCREEN_SUBTASKS },
      { name: 'ssrf-screen', label: 'SSRF', subtasks: SCREEN_SUBTASKS },
      { name: 'authz-screen', label: 'Authz', subtasks: SCREEN_SUBTASKS },
      { name: 'logic-screen', label: 'Logic', subtasks: SCREEN_SUBTASKS },
      { name: 'misconfig-web-screen', label: 'Web Misconfig', subtasks: SCREEN_SUBTASKS },
    ],
  },
  {
    id: 'exploitation',
    label: 'Validation',
    agents: [
      { name: 'injection-exploit', label: 'Injection', subtasks: EXPLOIT_SUBTASKS },
      { name: 'xss-exploit', label: 'XSS', subtasks: EXPLOIT_SUBTASKS },
      { name: 'auth-exploit', label: 'Auth', subtasks: EXPLOIT_SUBTASKS },
      { name: 'ssrf-exploit', label: 'SSRF', subtasks: EXPLOIT_SUBTASKS },
      { name: 'authz-exploit', label: 'Authz', subtasks: EXPLOIT_SUBTASKS },
      { name: 'logic-exploit', label: 'Logic', subtasks: EXPLOIT_SUBTASKS },
      { name: 'misconfig-web-exploit', label: 'Web Misconfig', subtasks: EXPLOIT_SUBTASKS },
    ],
  },
  {
    id: 'oracle',
    label: 'Adjudication',
    // Post-exploitation oracle: a deterministic replay SERVICE, not an LLM agent
    // (absent from the worker's ALL_AGENTS). The worker emits its progress under
    // the service key 'oracle' (ProgressEmitter.ServicePhaseAgent), so this single
    // tracked unit makes the card render running/done instead of "0/0 QUEUED".
    agents: [
      {
        name: 'oracle',
        label: 'Replay & adjudicate',
        subtasks: ['Replay captured PoCs', 'Match expected signals', 'Write dispositions'],
      },
    ],
  },
  {
    id: 'reporting',
    label: 'Sinas',
    agents: [{ name: 'report', label: 'Report', subtasks: ['Assemble findings', 'Write executive report'] }],
  },
  {
    id: 'attack-surface',
    label: 'Sinas',
    agents: [
      {
        name: 'attack-surface',
        label: 'Attack Surface',
        subtasks: ['Synthesize scenarios', 'Build kill chains', 'Generate fix prompts'],
      },
    ],
  },
];

/** Total agent count across all phases — the denominator for percent-complete. */
export const TOTAL_AGENTS: number = PIPELINE_PLAN.reduce((n, p) => n + p.agents.length, 0);

/** Skill → category (mirrors the repo `skills/<category>/` dirs). For the tool-arsenal grid. */
export type SkillCategory = 'recon' | 'exploit' | 'static-analysis';
export const SKILL_CATEGORY: Readonly<Record<string, SkillCategory>> = {
  arjun: 'recon', dnsx: 'recon', ffuf: 'recon', gau: 'recon', httpx: 'recon', katana: 'recon',
  kxss: 'recon', naabu: 'recon', nmap: 'recon', nuclei: 'recon', paramspider: 'recon',
  subfinder: 'recon', wafw00f: 'recon', waybackurls: 'recon',
  'authz-recipe': 'exploit', commix: 'exploit', dalfox: 'exploit', 'generate-totp': 'exploit',
  hydra: 'exploit', 'interactsh-client': 'exploit', jwt_tool: 'exploit', nosqli: 'exploit',
  playwright: 'exploit', sqlmap: 'exploit', ssrfmap: 'exploit', sstimap: 'exploit', xsstrike: 'exploit',
  gitleaks: 'static-analysis', 'osv-scanner': 'static-analysis', semgrep: 'static-analysis', trufflehog: 'static-analysis',
};
