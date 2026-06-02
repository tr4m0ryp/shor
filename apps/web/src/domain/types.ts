/**
 * Aegis shared domain types.
 *
 * The relational entities mirror LAUNCH-SPEC §4.3 (Cloud SQL schema) and the
 * `Finding` record mirrors §6.1 verbatim (the dashboard depends on this shape —
 * ADR-010/030/031). Dependent Phase 2-5 tasks import these as the canonical
 * contract.
 *
 * Project model (ADR-015):
 *   Tenant ─< Project ─< CodebaseVersion ─< Scan ─< { Finding, AttackSurface }
 */

// ───────────────────────────── shared scalars ─────────────────────────────

/** Branded id aliases — all are UUID strings at the DB layer. */
export type TenantId = string;
export type UserId = string;
export type ProjectId = string;
export type CodebaseVersionId = string;
export type ScanId = string;
export type FindingId = string;
export type ProviderKeyId = string;
export type AttackSurfaceId = string;

/** ISO-8601 timestamp string as returned/stored by Postgres. */
export type Timestamp = string;

// ──────────────────────────────── tenant ──────────────────────────────────

export interface Tenant {
  readonly id: TenantId;
  readonly orgName: string;
  /** Identity Platform tenant id (one IdP tenant per org — ADR-016/042). */
  readonly idpTenantId: string;
  readonly plan: string;
  readonly createdAt: Timestamp;
}

// ───────────────────────────────── user ───────────────────────────────────

/** Four-role RBAC (ADR-044). Each user belongs to exactly one tenant. */
export type UserRole = 'owner' | 'admin' | 'member' | 'viewer';

export const USER_ROLES: readonly UserRole[] = ['owner', 'admin', 'member', 'viewer'] as const;

export interface User {
  readonly id: UserId;
  readonly tenantId: TenantId;
  readonly email: string;
  readonly role: UserRole;
  readonly createdAt: Timestamp;
}

// ────────────────────────────── provider key ──────────────────────────────

/** LLM/tool providers whose key material lives in Secret Manager (ADR-017). */
export type Provider = 'anthropic' | 'openai' | 'deepseek' | 'openrouter' | 'vertex';

export interface ProviderKey {
  readonly id: ProviderKeyId;
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly provider: Provider;
  /** Secret Manager reference `aegis/<tenant>/<user>/<provider>`. NO key material in DB. */
  readonly secretRef: string;
  readonly createdAt: Timestamp;
}

// ──────────────────────────────── project ─────────────────────────────────

/** A named target = live site + connected repo + optional schedule (ADR-015). */
export interface Project {
  readonly id: ProjectId;
  readonly tenantId: TenantId;
  readonly name: string;
  readonly targetUrl: string;
  /** GitHub App installation id for the connected repo (ADR-039); null for zip-only. */
  readonly repoInstallationId: string | null;
  /** Cron-style schedule string, or null for on-demand. */
  readonly schedule: string | null;
  /** Target auth config (login flow, headers, ROE) — opaque JSON blob. */
  readonly authConfig: Record<string, unknown> | null;
  readonly createdAt: Timestamp;
}

// ─────────────────────────── codebase version ─────────────────────────────

export type CodebaseSourceKind = 'github' | 'zip';

/** Immutable snapshot minted per ingest (ADR-015). */
export interface CodebaseVersion {
  readonly id: CodebaseVersionId;
  readonly projectId: ProjectId;
  readonly sourceKind: CodebaseSourceKind;
  /** Resolved git SHA for github ingests; null for zip uploads. */
  readonly gitSha: string | null;
  /** GCS prefix `<tenantId>/<projectId>/<versionId>/` (ADR-037). */
  readonly gcsPrefix: string;
  readonly createdAt: Timestamp;
}

// ───────────────────────────────── scan ───────────────────────────────────

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export const SCAN_STATUSES: readonly ScanStatus[] = ['pending', 'running', 'completed', 'failed', 'cancelled'] as const;

/** Per-agent terminal record inside a {@link ScanProgress} snapshot. */
export interface AgentProgress {
  readonly agent: string;
  readonly status: 'completed' | 'failed';
  readonly durationMs: number;
}

/**
 * Live progress snapshot pushed by the worker as the pipeline walks its agents
 * (the per-scan run feed). Stored verbatim in `scan.progress` (JSONB); the read
 * route blends it with the static phase/agent taxonomy to render the activity
 * tab. Absent until the worker posts its first update.
 */
export interface ScanProgress {
  readonly status: ScanStatus;
  readonly currentPhase: string | null;
  readonly currentAgent: string | null;
  readonly failedAgent: string | null;
  /** Agents running concurrently right now (≥1 under 2-wide parallelism). */
  readonly runningAgents?: readonly string[];
  readonly completedAgents: readonly AgentProgress[];
  /** agent name → skills it has used so far (live, worker-pushed). */
  readonly skills?: Readonly<Record<string, readonly string[]>>;
  readonly updatedAt: string;
}

/** One pipeline run against a CodebaseVersion + live URL (ADR-015/019). */
export interface Scan {
  readonly id: ScanId;
  readonly projectId: ProjectId;
  readonly codebaseVersionId: CodebaseVersionId;
  /** Temporal workflow id (`aegis-<random>`); cancel = kill switch (ADR-019). */
  readonly temporalWorkflowId: string | null;
  readonly status: ScanStatus;
  readonly startedAt: Timestamp | null;
  readonly finishedAt: Timestamp | null;
  /** Live run-progress snapshot (worker-pushed); null until first update. */
  readonly progress: ScanProgress | null;
}

// ──────────────────────────────── finding ─────────────────────────────────

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'confirmed' | 'firm' | 'tentative';

/** Diff lifecycle computed via pgMemento on `fingerprint` (ADR-031/032). */
export type FindingStatus = 'new' | 'open' | 'fixed' | 'regressed';

export const FINDING_SEVERITIES: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'] as const;

export const FINDING_STATUSES: readonly FindingStatus[] = ['new', 'open', 'fixed', 'regressed'] as const;

/** file:line location for code findings (LAUNCH-SPEC §6.1). */
export interface VulnerableCodeLocation {
  readonly file: string;
  readonly line: number;
}

/**
 * The structured finding record — mirrors LAUNCH-SPEC §6.1 verbatim.
 *
 * Persisted as Postgres JSONB in storron's shape; SARIF 2.1.0 is an export
 * view only (ADR-033). `fingerprint` is the load-bearing stable diff key
 * (ADR-031): sha256(category + cwe + normalized_location + normalized_evidence).
 */
export interface FindingRecord {
  readonly id: string;
  readonly category: string;
  /** e.g. "CWE-89". */
  readonly cwe: string;
  /** e.g. "A03:2021-Injection". */
  readonly owasp_category: string;
  readonly severity: FindingSeverity;
  readonly confidence: FindingConfidence;
  readonly evidence: string;
  /** Harmless, reproducible proof-of-concept script (XBOW pattern). */
  readonly safe_poc: string;
  readonly repro_steps: string[];
  readonly vulnerable_code_location: VulnerableCodeLocation;
  readonly missing_defense: string;
  readonly remediation: string;
  readonly status: FindingStatus;

  /** Stable diff key (ADR-031, load-bearing). */
  readonly fingerprint: string;
  /** SARIF-style fuzzy fallback. */
  readonly partialFingerprints: Record<string, string>;

  /** Forward-compatible: tolerate additional fields from the emitter. */
  readonly [key: string]: unknown;
}

/** Persisted finding row (DB envelope around the §6.1 JSONB record). */
export interface Finding {
  readonly id: FindingId;
  readonly scanId: ScanId;
  readonly fingerprint: string;
  readonly status: FindingStatus;
  readonly data: FindingRecord;
  readonly createdAt: Timestamp;
}

// ────────────────────────────── attack surface ────────────────────────────

/**
 * Attack-surface synthesis — storron's scenario / kill-chain shape, stored as
 * JSONB (§4.3). Kept loosely typed: the worker emits the verbatim storron
 * `attack_surface_scenarios.json` document.
 */
export interface AttackSurfaceData extends Record<string, unknown> {
  readonly scenarios?: AttackScenario[];
}

export interface AttackScenario extends Record<string, unknown> {
  readonly id?: string;
  readonly title?: string;
  readonly kill_chain?: string[];
  /** Remediation ("fix") prompt for the connected repo (ADR-010). */
  readonly claude_code_prompt?: string;
}

export interface AttackSurface {
  readonly id: AttackSurfaceId;
  readonly scanId: ScanId;
  readonly data: AttackSurfaceData;
}

// ───────────────────────── insert / new-row shapes ────────────────────────
// Repositories accept these (server-generated columns omitted) on create.

export type NewTenant = Omit<Tenant, 'id' | 'createdAt'> & Partial<Pick<Tenant, 'plan'>>;
export type NewUser = Omit<User, 'id' | 'createdAt'>;
export type NewProviderKey = Omit<ProviderKey, 'id' | 'createdAt'>;
export type NewProject = Omit<Project, 'id' | 'createdAt'>;
export type NewCodebaseVersion = Omit<CodebaseVersion, 'id' | 'createdAt'>;
export type NewScan = Omit<Scan, 'id' | 'startedAt' | 'finishedAt' | 'progress'> &
  Partial<Pick<Scan, 'startedAt' | 'finishedAt'>>;
export type NewFinding = Omit<Finding, 'id' | 'createdAt'>;
export type NewAttackSurface = Omit<AttackSurface, 'id'>;
