/**
 * Ingest orchestration (LAUNCH-SPEC §4.1/4.2, ADR-015/039).
 *
 * `ingestForScan(project)` mints the immutable `CodebaseVersion` a scan runs
 * against:
 *   - `project.repoInstallationId` set  → GitHub pull of the default branch via
 *     the App installation (egress constrained to the installation allowlist).
 *   - otherwise                         → require a zip upload (callers pass the
 *     archive bytes through the options).
 *
 * Either path returns the new `CodebaseVersion`. Connecting a repo and choosing
 * github-vs-zip is a project property, so the dispatch lives here rather than in
 * the caller.
 */

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
}

/**
 * Mint the CodebaseVersion to scan for `project`.
 *
 * Dispatches on whether a GitHub App installation is connected. A project with
 * no installation MUST supply `options.zip`; a project with an installation
 * ignores any supplied zip and pulls from the repo (the connected repo is the
 * source of truth).
 */
export async function ingestForScan(project: Project, options: IngestForScanOptions): Promise<CodebaseVersion> {
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
