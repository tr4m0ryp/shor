/**
 * Project ingest — public surface (LAUNCH-SPEC §4.2, Phase 4, ADR-039/040/041).
 *
 * Connect a repo via the Aegis GitHub App or accept a zip upload, store the
 * source artifacts in GCS, and mint an immutable `CodebaseVersion`. Clone egress
 * is constrained to the App-installation allowlist (no arbitrary-host clone).
 *
 * Entry point: `ingestForScan(project, options)` dispatches github-vs-zip on the
 * project's connected-repo state and returns the new `CodebaseVersion`.
 */

export {
  type InstallationRepo,
  type InstallationToken,
  findInstallationRepo,
  installationRepos,
  installationToken,
} from './github-app.js';
export {
  type RepoSlug,
  assertInstallationRepo,
  isInstallationGitUrl,
  parseGithubRepoUrl,
} from './git-url.js';
export { type GithubIngestInput, ingestGithub } from './git-source.js';
export { type ZipIngestInput, MAX_ZIP_BYTES, ingestZip, isZipBuffer } from './zip-source.js';
export { type IngestForScanOptions, ingestForScan } from './ingest.js';
