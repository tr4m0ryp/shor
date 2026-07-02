// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * GitHub source ingest via a per-user Personal Access Token (LAUNCH-SPEC §4.2).
 *
 * White-box scans clone the project's selected repo (`owner/name`) with the
 * scanning user's PAT — there is no GitHub App installation or allowlist. The
 * PAT is injected into the HTTPS clone URL as userinfo
 * (`x-access-token:<pat>@github.com/<owner/name>.git`), the standard GitHub
 * token-clone idiom; it is never logged and the temp checkout is removed in
 * `finally`, so the token never lingers on disk.
 *
 * Flow: clone the selected repo to a temp dir → resolve the git SHA → tar the
 * working tree → `putObject` to GCS under `objectPrefix(tenant, project, version)`
 * → mint an immutable `CodebaseVersion` (source `github`, `git_sha` recorded).
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

/** Inputs for a github ingest of one selected repo via a user PAT. */
export interface GithubIngestInput {
  readonly tenantId: TenantId;
  readonly project: Project;
  /** Selected repo `owner/name` to clone. */
  readonly repoFullName: string;
  /** The scanning user's GitHub PAT used to clone (private repos included). */
  readonly pat: string;
  /** Branch/ref to pull; defaults to the repo's default branch. */
  readonly ref?: string;
}

/**
 * Ingest a GitHub repo into an immutable CodebaseVersion using the user's PAT.
 *
 * Clones `owner/name` over HTTPS with the PAT, tars the working tree, stages it
 * in GCS, and mints the version row. When no `ref` is given, the default branch
 * is cloned via `--branch HEAD`-equivalent (git resolves the remote HEAD).
 */
export async function ingestGithub(input: GithubIngestInput): Promise<CodebaseVersion> {
  const fullName = assertFullName(input.repoFullName);

  const versionId = randomUUID();
  const prefix = objectPrefix(input.tenantId, input.project.id, versionId);
  const workdir = mkdtempSync(join(tmpdir(), 'shor-clone-'));
  const checkout = join(workdir, 'repo');

  try {
    cloneRepo(fullName, input.ref, input.pat, checkout);
    const gitSha = resolveSha(checkout);
    const archive = tarWorkingTree(checkout);

    await putObject(`${prefix}source.tar`, archive, 'application/x-tar');
    await putObject(`${prefix}metadata.json`, sourceMetadata(fullName, input.ref, gitSha), 'application/json');

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

/** Validate the `owner/name` shape before constructing a clone URL. */
function assertFullName(fullName: string): string {
  if (!/^[^/\s]+\/[^/\s]+$/.test(fullName)) {
    throw new Error(`github ingest: repoFullName must be "owner/name", got "${fullName}"`);
  }
  return fullName;
}

/**
 * Clone the selected repo over HTTPS using the user's PAT.
 *
 * The PAT is injected as the URL userinfo (`x-access-token:<pat>@github.com/…`).
 * `--single-branch` + an explicit `--branch <ref>` are used only when a ref is
 * given; otherwise git clones the remote default branch. `--depth`/`--no-tags`
 * keep the snapshot shallow. The PAT is NEVER logged.
 */
function cloneRepo(fullName: string, ref: string | undefined, pat: string, dest: string): void {
  const depth = getConfig().github.cloneDepth;
  const authedUrl = withToken(`https://github.com/${fullName}.git`, pat);
  const args = [
    'clone',
    '--depth',
    String(depth),
    '--single-branch',
    ...(ref ? ['--branch', ref] : []),
    '--no-tags',
    authedUrl,
    dest,
  ];
  try {
    execFileSync('git', args, { stdio: 'pipe' });
  } catch (err) {
    // Scrub the PAT out of any surfaced git error (it embeds the clone URL).
    const msg = sanitize(err instanceof Error ? err.message : String(err), pat);
    throw new Error(`git clone failed for ${fullName}${ref ? `@${ref}` : ''}: ${msg}`);
  }
}

/** Inject the PAT into an HTTPS clone URL as userinfo. */
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
function sourceMetadata(fullName: string, ref: string | undefined, gitSha: string): string {
  return JSON.stringify({ sourceKind: 'github', repo: fullName, ref: ref ?? null, gitSha }, null, 2);
}

/** Replace every occurrence of the token in a string with a redaction marker. */
function sanitize(text: string, token: string): string {
  return token ? text.split(token).join('***') : text;
}
