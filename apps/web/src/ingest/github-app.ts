// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * GitHub App authentication (LAUNCH-SPEC §4.2, ADR-039).
 *
 * One Shor App, per-tenant installation. We mint a SHORT-LIVED installation
 * token per scan (never a PAT — ADR-039) so clone egress is scoped to exactly
 * the repositories the tenant installed the App on (ADR-041).
 *
 * Secret handling:
 *   - The numeric App id is non-secret config (`config.github.appId`).
 *   - The App private key (PEM) lives ONLY in Secret Manager and is read on
 *     demand via `config.github.privateKeySecretRef`. It is never logged, never
 *     persisted to the DB, and never returned to callers.
 *
 * Lazy client: `@octokit/auth-app` is dynamically imported on first use so this
 * module performs no I/O at import time and `tsc`/`build` need no live App key.
 */

import type { StrategyOptions } from '@octokit/auth-app';
import { getConfig } from '../config.js';
import { getSecret } from '../cloud/secret-manager.js';

/** A minted installation token plus the metadata a caller needs to use it. */
export interface InstallationToken {
  /** The `ghs_…` installation access token. Treat as a secret; do not log. */
  readonly token: string;
  /** Owning installation id the token is scoped to. */
  readonly installationId: number;
  /** ISO-8601 expiry; installation tokens are short-lived (~1h). */
  readonly expiresAt: string;
}

/** One repository visible to an installation (the clone allowlist, ADR-041). */
export interface InstallationRepo {
  readonly id: number;
  /** `owner/name`. */
  readonly fullName: string;
  readonly cloneUrl: string;
  readonly defaultBranch: string;
  readonly private: boolean;
}

interface AuthStrategy {
  (opts: { type: 'installation'; installationId: number }): Promise<{
    token: string;
    expiresAt: string;
  }>;
}

/** Resolve App id + private key (PEM from Secret Manager) into auth options. */
async function appAuthOptions(): Promise<StrategyOptions> {
  const { appId, privateKeySecretRef } = getConfig().github;
  if (!appId) {
    throw new Error('GitHub App is not configured: set GITHUB_APP_ID');
  }
  const privateKey = await getSecret(privateKeySecretRef);
  if (!privateKey) {
    throw new Error(`GitHub App private key not found at secret ref "${privateKeySecretRef}"`);
  }
  return { appId, privateKey };
}

/** Build a lazily-imported app auth strategy bound to the configured App. */
async function appAuth(): Promise<AuthStrategy> {
  const mod = await import('@octokit/auth-app');
  return mod.createAppAuth(await appAuthOptions()) as unknown as AuthStrategy;
}

/**
 * Mint a short-lived installation access token for `installationId`.
 *
 * The token is scoped to the installation's repositories only; we never widen
 * it. Callers should use it immediately (clone) and discard it — never persist.
 */
export async function installationToken(installationId: number): Promise<InstallationToken> {
  const auth = await appAuth();
  const { token, expiresAt } = await auth({ type: 'installation', installationId });
  return { token, installationId, expiresAt };
}

/**
 * List the repositories an installation can access — the clone allowlist used
 * to constrain egress (ADR-041). Paginates the installation-token-scoped
 * `GET /installation/repositories` endpoint via a lazily-imported request.
 */
export async function installationRepos(installationId: number): Promise<InstallationRepo[]> {
  const { token } = await installationToken(installationId);
  const mod = await import('@octokit/request');
  const repos: InstallationRepo[] = [];

  for (let page = 1; ; page++) {
    const res = await mod.request('GET /installation/repositories', {
      per_page: 100,
      page,
      headers: { authorization: `token ${token}` },
    });
    const batch = (res.data.repositories ?? []) as Array<{
      id: number;
      full_name: string;
      clone_url: string;
      default_branch: string;
      private: boolean;
    }>;
    for (const r of batch) {
      repos.push({
        id: r.id,
        fullName: r.full_name,
        cloneUrl: r.clone_url,
        defaultBranch: r.default_branch,
        private: r.private,
      });
    }
    if (batch.length < 100) break;
  }

  return repos;
}

/**
 * Resolve a single installation repo, matched by `owner/name`, or `null` when
 * the installation cannot access it. The basis for the clone allowlist check.
 */
export async function findInstallationRepo(
  installationId: number,
  fullName: string,
): Promise<InstallationRepo | null> {
  const target = fullName.toLowerCase();
  const repos = await installationRepos(installationId);
  return repos.find((r) => r.fullName.toLowerCase() === target) ?? null;
}
