// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Identity service (task 008 — multi-identity provisioning).
 *
 * Public surface:
 *   - {@link bootstrapIdentities} — the pipeline hook (best-effort) that
 *     provisions per-identity session slots and writes `scan_identities.json`.
 *   - {@link collectIdentities} / {@link ResolvedIdentity} — derive the ordered,
 *     credential-free identity set from the auth config.
 *   - {@link buildIdentityManifest} / {@link writeIdentityManifest} — the
 *     metadata-only manifest producer (label/role; matches the assembler reader).
 *   - session helpers — per-identity Playwright storage-state seam.
 */

export { bootstrapIdentities } from "./bootstrap.js";
export {
	collectIdentities,
	PRIMARY_IDENTITY_LABEL,
	type ResolvedIdentity,
} from "./collect.js";
export {
	buildIdentityManifest,
	type IdentityManifest,
	type IdentityManifestEntry,
	SINGLE_IDENTITY_NOTE,
	writeIdentityManifest,
} from "./manifest.js";
export {
	identityStorageStatePath,
	playwrightSessionsRoot,
	type ProvisionedIdentity,
	provisionIdentitySession,
} from "./session.js";
