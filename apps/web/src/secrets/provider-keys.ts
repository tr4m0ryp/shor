// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-user provider-key management (LAUNCH-SPEC §3.2, ADR-017 / ADR-045).
 *
 * One secret resource per (tenant, user, provider). Key material lives ONLY in
 * Secret Manager; Postgres `provider_key` rows hold the `secretRef` and never
 * the material itself (ADR-050). Every operation is tenant-scoped.
 *
 * Flow on store/rotate:
 *   1. `secretRef(tenant, user, provider)` derives the canonical reference.
 *   2. `setSecret(ref, material)` writes a new Secret Manager version.
 *   3. `providerKeyRepo.upsert` records the ref (idempotent on the triple).
 */

import { secretRef, setSecret, deleteSecret } from '../cloud/secret-manager.js';
import { providerKeyRepo } from '../db/repositories/index.js';
import type { Provider, ProviderKey, TenantId, UserId } from '../domain/types.js';

/**
 * Store (or replace) the key material for a (tenant, user, provider) triple.
 *
 * Writes the material to Secret Manager as a new version, then upserts the
 * `secretRef` into Postgres. NO key material is persisted in the DB. Returns the
 * resulting `ProviderKey` row (secretRef only).
 */
export async function storeProviderKey(
  tenantId: TenantId,
  userId: UserId,
  provider: Provider,
  keyMaterial: string,
): Promise<ProviderKey> {
  if (!keyMaterial) {
    throw new Error('storeProviderKey: keyMaterial must be a non-empty string');
  }
  const ref = secretRef(tenantId, userId, provider);
  await setSecret(ref, keyMaterial);
  return providerKeyRepo.upsert({ tenantId, userId, provider, secretRef: ref });
}

/**
 * Rotate the key material: add a new Secret Manager version at the same ref.
 *
 * The `secretRef` is stable across rotations, so this is `storeProviderKey`
 * with intent-revealing naming. Returns the (unchanged-ref) `ProviderKey`.
 */
export async function rotateProviderKey(
  tenantId: TenantId,
  userId: UserId,
  provider: Provider,
  newKeyMaterial: string,
): Promise<ProviderKey> {
  return storeProviderKey(tenantId, userId, provider, newKeyMaterial);
}

/**
 * Delete the provider key for a (tenant, user, provider) triple: removes the
 * Secret Manager secret (all versions) and the Postgres row. Idempotent — a
 * missing secret or row is treated as already-deleted.
 */
export async function deleteProviderKey(
  tenantId: TenantId,
  userId: UserId,
  provider: Provider,
): Promise<void> {
  const existing = await providerKeyRepo.findForUserProvider(tenantId, userId, provider);
  const ref = existing?.secretRef ?? secretRef(tenantId, userId, provider);
  await deleteSecret(ref);
  if (existing) {
    await providerKeyRepo.delete(tenantId, existing.id);
  }
}

/**
 * List every provider key configured for a user (secretRef only, no material).
 * Tenant-scoped.
 */
export async function listForUser(tenantId: TenantId, userId: UserId): Promise<ProviderKey[]> {
  return providerKeyRepo.listByUser(tenantId, userId);
}
