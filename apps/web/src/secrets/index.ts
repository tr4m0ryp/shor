// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-user secrets management — public surface (LAUNCH-SPEC §3.2, ADR-017/045/050).
 *
 * `provider-keys` writes/rotates/deletes key material in Secret Manager and
 * records only the `secretRef` in Postgres. `injection` derives the per-run
 * file-mount + scoped service-identity binding manifest for a scan.
 */

export {
  storeProviderKey,
  rotateProviderKey,
  deleteProviderKey,
  listForUser,
} from './provider-keys.js';

export {
  buildInjectionManifest,
  PROVIDER_KEY_FILE_ENV,
  PROVIDER_KEY_MOUNT_DIR,
  PROVIDER_KEY_FILE_NAME,
  type FileMountSecret,
  type InjectionManifest,
  type SecretAccessBinding,
} from './injection.js';
