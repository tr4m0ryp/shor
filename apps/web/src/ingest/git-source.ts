/**
 * GitHub source ingest (LAUNCH-SPEC §4.2, ADR-039/040/041).
 *
 * Ports storron's `uploads/git.ts` clone pattern, TIGHTENED for multi-tenant:
 *   - No arbitrary-host clone. The only repos that can be cloned are those in
 *     the App-installation allowlist (`assertInstallationRepo`) — the open
 *     `cloneRepo(gitUrl)` SSRF surface is removed (ADR-041).
 *   - Auth via a short-lived installation token injected into the HTTPS clone
 *     URL, never a PAT or a long-lived credential (ADR-039).
 *   - `--depth 1` default (ADR-040).
 *
 * Flow: mint installation token → clone the allowlisted repo to a temp dir →
 * resolve the git SHA → tar the working tree → `putObject` to GCS under
 * `objectPrefix(tenant, project, version)` → mint an immutable `CodebaseVersion`
 * (source `github`, `git_sha` recorded) via `codebaseVersionRepo`.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { getConfig } from '../config.js';
import { objectPrefix, putObject } from '../cloud/storage.js';
import { codebaseVersionRepo } from '../db/repositories/index.js';
import type { CodebaseVersion, Project, TenantId } from '../domain/types.js';
import { assertInstallationRepo } from './git-url.js';
import { type InstallationRepo, installationRepos, installationToken } from './github-app.js';

/** Inputs for a github ingest of one allowlisted repo. */
export interface GithubIngestInput {
  readonly tenantId: TenantId;
  readonly project: Project;
  /** Installation that owns the App grant for this repo. */
  readonly installationId: number;
  /** `owner/name` of the repo to pull. Defaults to the installation's sole repo. */
  readonly repoFullName?: string;
  /** Branch/ref to pull; defaults to the repo's default branch. */
  readonly ref?: string;
}

/**
 * Ingest a GitHub repo into an immutable CodebaseVersion.
 *
 * Clone egress is constrained to the installation allowlist; a non-allowlisted
 * repo throws before any `git` process is spawned.
 */
export async function ingestGithub(input: GithubIngestInput): Promise<CodebaseVersion> {
  const allowlist = await installationRepos(input.installationId);
  const repo = resolveRepo(input, allowlist);
  const ref = input.ref ?? repo.defaultBranch;

  const versionId = randomUUID();
  const prefix = objectPrefix(input.tenantId, input.project.id, versionId);
  const workdir = mkdtempSync(join(tmpdir(), 'aegis-clone-'));
  const checkout = join(workdir, 'repo');

  try {
    const { token } = await installationToken(input.installationId);
    cloneAllowlisted(repo, ref, token, checkout);
    const gitSha = resolveSha(checkout);
    const archive = tarWorkingTree(checkout);

    await putObject(`${prefix}source.tar`, archive, 'application/x-tar');
    await putObject(`${prefix}metadata.json`, sourceMetadata(repo, ref, gitSha), 'application/json');

    return codebaseVersionRepo.create({
      projectId: input.project.id,
      sourceKind: 'github',
      gitSha,
      gcsPrefix: prefix,
    });
  } finally {
    // Always remove the checkout (and any leftover token in the git config).
    rmSync(workdir, { recursive: true, force: true });
  }
}

/** Pick the target repo: explicit `owner/name`, else the installation's sole repo. */
function resolveRepo(input: GithubIngestInput, allowlist: InstallationRepo[]): InstallationRepo {
  if (input.repoFullName) {
    return assertInstallationRepo(input.repoFullName, allowlist);
  }
  if (allowlist.length === 1) {
    return allowlist[0] as InstallationRepo;
  }
  throw new Error(
    'github ingest requires repoFullName when the installation grants access to multiple repos',
  );
}

/**
 * Clone exactly one allowlisted repo over HTTPS using the short-lived token.
 *
 * The token is injected as the URL userinfo (`x-access-token:<token>@…`) — the
 * standard GitHub App clone idiom. We pass it via the URL rather than env to
 * keep the surface small; the temp dir is removed in the caller's `finally`, so
 * the token never lingers on disk beyond the clone. The token is NEVER logged.
 */
function cloneAllowlisted(repo: InstallationRepo, ref: string, token: string, dest: string): void {
  const depth = getConfig().github.cloneDepth;
  const authedUrl = withToken(repo.cloneUrl, token);
  const args = [
    'clone',
    '--depth',
    String(depth),
    '--single-branch',
    '--branch',
    ref,
    '--no-tags',
    authedUrl,
    dest,
  ];
  try {
    execFileSync('git', args, { stdio: 'pipe' });
  } catch (err) {
    // Scrub the token out of any surfaced git error (it embeds the clone URL).
    const msg = sanitize(err instanceof Error ? err.message : String(err), token);
    throw new Error(`git clone failed for ${repo.fullName}@${ref}: ${msg}`);
  }
}

/** Inject the installation token into an HTTPS clone URL as userinfo. */
function withToken(cloneUrl: string, token: string): string {
  const u = new URL(cloneUrl);
  u.username = 'x-access-token';
  u.password = token;
  return u.toString();
}

/** Resolve the checked-out commit SHA (records provenance on the version). */
function resolveSha(checkout: string): string {
  const sha = execFileSync('git', ['-C', checkout, 'rev-parse', 'HEAD'], { stdio: 'pipe' });
  return sha.toString('utf8').trim();
}

/** Tar the working tree (excluding `.git`) into an in-memory buffer for GCS. */
function tarWorkingTree(checkout: string): Buffer {
  const out = join(checkout, '..', 'source.tar');
  execFileSync('tar', ['--exclude=./.git', '-cf', out, '-C', checkout, '.'], { stdio: 'pipe' });
  const buf = readFileSync(out);
  rmSync(out, { force: true });
  return buf;
}

/** Provenance sidecar stored next to the archive (no secrets). */
function sourceMetadata(repo: InstallationRepo, ref: string, gitSha: string): string {
  return JSON.stringify(
    { sourceKind: 'github', repo: repo.fullName, ref, gitSha, private: repo.private },
    null,
    2,
  );
}

/** Replace every occurrence of the token in a string with a redaction marker. */
function sanitize(text: string, token: string): string {
  return token ? text.split(token).join('***') : text;
}
