/**
 * Row-mapping helpers shared across repositories.
 *
 * Postgres returns snake_case columns + TIMESTAMPTZ as JS Date (via node-pg).
 * Each repo maps its DB row to the camelCase domain type with these helpers so
 * mapping stays consistent and each repo file stays well under the 300-line cap.
 */

import type {
  AttackSurface,
  AttackSurfaceData,
  CodebaseSourceKind,
  CodebaseVersion,
  Finding,
  FindingRecord,
  FindingStatus,
  Project,
  Provider,
  ProviderKey,
  Scan,
  ScanStatus,
  Tenant,
  User,
  UserRole,
} from '../../domain/types.js';

/** Coerce a TIMESTAMPTZ column (Date | string | null) to an ISO string | null. */
export function ts(value: unknown): string {
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

export function tsOrNull(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return ts(value);
}

export interface TenantRow {
  id: string;
  org_name: string;
  idp_tenant_id: string;
  plan: string;
  created_at: unknown;
}

export function toTenant(r: TenantRow): Tenant {
  return {
    id: r.id,
    orgName: r.org_name,
    idpTenantId: r.idp_tenant_id,
    plan: r.plan,
    createdAt: ts(r.created_at),
  };
}

export interface UserRow {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  created_at: unknown;
}

export function toUser(r: UserRow): User {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    email: r.email,
    role: r.role as UserRole,
    createdAt: ts(r.created_at),
  };
}

export interface ProviderKeyRow {
  id: string;
  tenant_id: string;
  user_id: string;
  provider: string;
  secret_ref: string;
  created_at: unknown;
}

export function toProviderKey(r: ProviderKeyRow): ProviderKey {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    userId: r.user_id,
    provider: r.provider as Provider,
    secretRef: r.secret_ref,
    createdAt: ts(r.created_at),
  };
}

export interface ProjectRow {
  id: string;
  tenant_id: string;
  name: string;
  target_url: string;
  repo_installation_id: string | null;
  repo_full_name: string | null;
  mode: string;
  schedule: string | null;
  auth_config: Record<string, unknown> | null;
  roe: Record<string, unknown> | null;
  share_slug: string | null;
  created_at: unknown;
}

export function toProject(r: ProjectRow): Project {
  return {
    id: r.id,
    tenantId: r.tenant_id,
    name: r.name,
    targetUrl: r.target_url,
    repoInstallationId: r.repo_installation_id,
    repoFullName: r.repo_full_name,
    mode: r.mode === 'whitebox' ? 'whitebox' : 'blackbox',
    schedule: r.schedule,
    authConfig: r.auth_config,
    shareSlug: r.share_slug ?? null,
    createdAt: ts(r.created_at),
  };
}

export interface CodebaseVersionRow {
  id: string;
  project_id: string;
  source_kind: string;
  git_sha: string | null;
  gcs_prefix: string;
  created_at: unknown;
}

export function toCodebaseVersion(r: CodebaseVersionRow): CodebaseVersion {
  return {
    id: r.id,
    projectId: r.project_id,
    sourceKind: r.source_kind as CodebaseSourceKind,
    gitSha: r.git_sha,
    gcsPrefix: r.gcs_prefix,
    createdAt: ts(r.created_at),
  };
}

export interface ScanRow {
  id: string;
  project_id: string;
  codebase_ver_id: string | null;
  temporal_workflow_id: string | null;
  status: string;
  started_at: unknown;
  finished_at: unknown;
  progress?: unknown;
}

export function toScan(r: ScanRow): Scan {
  return {
    id: r.id,
    projectId: r.project_id,
    codebaseVersionId: r.codebase_ver_id,
    temporalWorkflowId: r.temporal_workflow_id,
    status: r.status as ScanStatus,
    startedAt: tsOrNull(r.started_at),
    finishedAt: tsOrNull(r.finished_at),
    progress: (r.progress as Scan['progress']) ?? null,
  };
}

export interface FindingRow {
  id: string;
  scan_id: string;
  fingerprint: string;
  data: FindingRecord;
  status: string;
  created_at: unknown;
}

export function toFinding(r: FindingRow): Finding {
  return {
    id: r.id,
    scanId: r.scan_id,
    fingerprint: r.fingerprint,
    status: r.status as FindingStatus,
    data: r.data,
    createdAt: ts(r.created_at),
  };
}

export interface AttackSurfaceRow {
  id: string;
  scan_id: string;
  data: AttackSurfaceData;
}

export function toAttackSurface(r: AttackSurfaceRow): AttackSurface {
  return { id: r.id, scanId: r.scan_id, data: r.data };
}
