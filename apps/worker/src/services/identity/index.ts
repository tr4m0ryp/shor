// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
