/**
 * Ingest orchestration (LAUNCH-SPEC §4.1/4.2, ADR-015/039).
 *
 * `ingestForScan(project, options)` resolves the immutable `CodebaseVersion` a
 * scan runs against, or `null` for black-box scans:
 *   - black-box (`project.mode === 'blackbox'` or no `repoFullName`) → `null`:
 *     the pipeline runs against just the target URL, no code is staged.
 *   - white-box → clone `project.repoFullName` with the SCANNING USER's GitHub
 *     PAT and mint a `CodebaseVersion`. Source already staged in GCS is reused
 *     unless `forceFresh` is set.
 *
 * Choosing white-box-vs-black-box is a project property, so the dispatch lives
 * here rather than in the caller.
 */

import { codebaseVersionRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, TenantId, UserId } from '../domain/types.js';
import { getGithubToken } from '../github/index.js';
import { ingestGithub } from './git-source.js';

/** Per-scan ingest options. */
export interface IngestForScanOptions {
  /** Tenant that owns `project`. Required for the GCS prefix + version scoping. */
  readonly tenantId: TenantId;
  /** The scanning user whose stored GitHub PAT clones the selected repo. */
  readonly userId: UserId;
  /** Git ref to pull; defaults to the repo's default branch (white-box only). */
  readonly ref?: string;
  /**
   * Skip GCS reuse and always ingest a fresh snapshot. Default false — when a
   * version already exists for the project (source already staged in GCS), it is
   * reused so seeded/test projects need no GitHub pull.
   */
  readonly forceFresh?: boolean;
}

/**
 * Resolve the CodebaseVersion to scan for `project`, or `null` for black-box.
 *
 * Black-box projects (no selected repo) return `null` — the scan carries no
 * codebase version. White-box projects clone the selected repo via the scanning
 * user's PAT; unless `forceFresh`, an already-staged latest version is reused so
 * seeded/test projects scan without a GitHub pull. A white-box project whose
 * owner has no stored PAT throws (the caller surfaces a 4xx/5xx).
 */
export async function ingestForScan(
  project: Project,
  options: IngestForScanOptions,
): Promise<CodebaseVersion | null> {
  // Black-box: no repo selected → no codebase version.
  if (project.mode === 'blackbox' || !project.repoFullName) {
    return null;
  }

  if (!options.forceFresh) {
    const existing = await codebaseVersionRepo.latestForProject(options.tenantId, project.id);
    if (existing) return existing;
  }

  const pat = await getGithubToken(options.tenantId, options.userId);
  if (!pat) {
    throw new Error(
      `white-box scan requires a connected GitHub token; none stored for user ${options.userId}`,
    );
  }

  return ingestGithub({
    tenantId: options.tenantId,
    project,
    repoFullName: project.repoFullName,
    pat,
    ...(options.ref !== undefined ? { ref: options.ref } : {}),
  });
}
