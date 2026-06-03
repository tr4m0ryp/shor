/**
 * Per-user GitHub Personal Access Token (PAT) storage.
 *
 * One PAT per (tenant, user), stored under the `github` provider slot in Secret
 * Manager (`shor/<tenant>/<user>/github`). The Postgres `provider_key` row holds
 * only the `secretRef` — the token material lives ONLY in Secret Manager
 * (ADR-017/050). The token authenticates repo listing and white-box clones.
 *
 * `provider` for these helpers is the literal `'github'`. The shared
 * `provider_key` columns are plain TEXT, so the row stores it directly; the
 * domain `Provider` union does not include `'github'`, hence the local cast at
 * the repository boundary (the only place that union is enforced).
 */

import { secretRef, getSecret, setSecret, deleteSecret } from '../cloud/secret-manager.js';
import { providerKeyRepo } from '../db/repositories/index.js';
import type { Provider, TenantId, UserId } from '../domain/types.js';

/** Provider slot the GitHub PAT occupies in Secret Manager + `provider_key`. */
const GITHUB_PROVIDER = 'github';

/**
 * Store (or replace) the caller's GitHub PAT for a (tenant, user) pair. Writes
 * the token to Secret Manager as a new version, then upserts the `secretRef`
 * into `provider_key`. NO token material is persisted in the DB.
 */
export async function storeGithubToken(tenantId: TenantId, userId: UserId, pat: string): Promise<void> {
  if (!pat) {
    throw new Error('storeGithubToken: pat must be a non-empty string');
  }
  const ref = secretRef(tenantId, userId, GITHUB_PROVIDER);
  await setSecret(ref, pat);
  await providerKeyRepo.upsert({ tenantId, userId, provider: GITHUB_PROVIDER as Provider, secretRef: ref });
}

/**
 * Read the caller's GitHub PAT for a (tenant, user) pair. Returns the token
 * string, or `null` when none is configured.
 */
export async function getGithubToken(tenantId: TenantId, userId: UserId): Promise<string | null> {
  const ref = secretRef(tenantId, userId, GITHUB_PROVIDER);
  return getSecret(ref);
}

/**
 * Delete the caller's GitHub PAT: removes the Secret Manager secret (all
 * versions) and the `provider_key` row. Idempotent.
 */
export async function deleteGithubToken(tenantId: TenantId, userId: UserId): Promise<void> {
  const existing = await providerKeyRepo.findForUserProvider(tenantId, userId, GITHUB_PROVIDER as Provider);
  const ref = existing?.secretRef ?? secretRef(tenantId, userId, GITHUB_PROVIDER);
  await deleteSecret(ref);
  if (existing) {
    await providerKeyRepo.delete(tenantId, existing.id);
  }
}
