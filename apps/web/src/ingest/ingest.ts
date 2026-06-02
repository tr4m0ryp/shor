/**
 * Ingest orchestration (LAUNCH-SPEC §4.1/4.2, ADR-015/039).
 *
 * `ingestForScan(project)` mints (or reuses) the immutable `CodebaseVersion` a
 * scan runs against:
 *   - source already staged in GCS  → reuse the latest existing
 *     `CodebaseVersion` for the project (seeded/test projects need no pull or
 *     zip). Pass `forceFresh: true` to skip reuse and ingest anew.
 *   - `project.repoInstallationId` set  → GitHub pull of the default branch via
 *     the App installation (egress constrained to the installation allowlist).
 *   - otherwise                         → require a zip upload (callers pass the
 *     archive bytes through the options).
 *
 * Each path returns a `CodebaseVersion`. Connecting a repo and choosing
 * github-vs-zip is a project property, so the dispatch lives here rather than in
 * the caller.
 */

import { codebaseVersionRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, TenantId } from '../domain/types.js';
import { ingestGithub } from './git-source.js';
import { ingestZip } from './zip-source.js';

/** Per-scan ingest options. */
export interface IngestForScanOptions {
  /** Tenant that owns `project`. Required for the GCS prefix + version scoping. */
  readonly tenantId: TenantId;
  /** Explicit `owner/name` for multi-repo installations; default branch is used. */
  readonly repoFullName?: string;
  /** Git ref to pull; defaults to the repo's default branch (github path only). */
  readonly ref?: string;
  /** Uploaded zip bytes — required when the project has no connected repo. */
  readonly zip?: { readonly archive: Buffer; readonly filename?: string; readonly maxBytes?: number };
  /**
   * Skip GCS reuse and always ingest a fresh snapshot. Default false — when a
   * version already exists for the project (source already staged in GCS), it is
   * reused so seeded/test projects need no GitHub pull or zip upload.
   */
  readonly forceFresh?: boolean;
}

/**
 * Mint (or reuse) the CodebaseVersion to scan for `project`.
 *
 * Reuse first: unless `forceFresh`, an already-staged latest version is returned
 * so seeded/test projects scan without a GitHub pull or zip. Otherwise dispatches
 * on whether a GitHub App installation is connected. A project with no
 * installation MUST supply `options.zip`; a project with an installation ignores
 * any supplied zip and pulls from the repo (the connected repo is the source of
 * truth).
 */
export async function ingestForScan(project: Project, options: IngestForScanOptions): Promise<CodebaseVersion> {
  if (!options.forceFresh) {
    const existing = await codebaseVersionRepo.latestForProject(options.tenantId, project.id);
    if (existing) return existing;
  }

  if (project.repoInstallationId) {
    const installationId = Number.parseInt(project.repoInstallationId, 10);
    if (!Number.isFinite(installationId)) {
      throw new Error(`project ${project.id} has a non-numeric repoInstallationId`);
    }
    return ingestGithub({
      tenantId: options.tenantId,
      project,
      installationId,
      ...(options.repoFullName !== undefined ? { repoFullName: options.repoFullName } : {}),
      ...(options.ref !== undefined ? { ref: options.ref } : {}),
    });
  }

  if (!options.zip) {
    throw new Error(`project ${project.id} has no connected repo; a zip upload is required to ingest`);
  }
  return ingestZip({
    tenantId: options.tenantId,
    project,
    archive: options.zip.archive,
    ...(options.zip.filename !== undefined ? { filename: options.zip.filename } : {}),
    ...(options.zip.maxBytes !== undefined ? { maxBytes: options.zip.maxBytes } : {}),
  });
}
