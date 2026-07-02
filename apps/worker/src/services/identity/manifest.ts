// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Producer for `scan_identities.json` — the per-scan identity manifest the
 * threat-model assembler reads (`services/threat-model/artifacts.ts ->
 * renderIdentities`). The shape is intentionally minimal and MUST stay in lock-
 * step with that reader: `{ identities: [{ label, role? }], note? }`.
 *
 * METADATA ONLY (ADR-050). The manifest is built from {@link ResolvedIdentity},
 * which by construction carries no credential material, so a username / password
 * / token / cookie / TOTP secret can never reach this file. The optional `note`
 * is non-secret prose the reader ignores (it only consumes `identities`).
 */

import { fs, path } from "zx";
import { SCAN_IDENTITIES_FILE } from "../threat-model/index.js";
import type { ResolvedIdentity } from "./collect.js";

/** One manifest row — label/role only, never a secret. */
export interface IdentityManifestEntry {
	label: string;
	role?: string;
}

/** Serialized `scan_identities.json` document. */
export interface IdentityManifest {
	identities: IdentityManifestEntry[];
	note?: string;
}

/** Appended when fewer than two identities are provisioned. */
export const SINGLE_IDENTITY_NOTE =
	"Single-identity authorization coverage: only one identity was provisioned, " +
	"so cross-account / privilege-escalation checks (IDOR/BOLA) cannot compare " +
	"identity A against identity B.";

/**
 * Project the resolved identities down to the label/role allowlist and attach
 * the single-identity note when authz coverage is degraded (< 2 identities).
 */
export function buildIdentityManifest(
	identities: ResolvedIdentity[],
): IdentityManifest {
	const entries: IdentityManifestEntry[] = identities.map((identity) => ({
		label: identity.label,
		...(identity.role !== undefined && { role: identity.role }),
	}));
	return {
		identities: entries,
		...(entries.length < 2 && { note: SINGLE_IDENTITY_NOTE }),
	};
}

/**
 * Write the manifest to `<deliverablesPath>/scan_identities.json` (the exact
 * path + filename the assembler reads). Returns the absolute file path.
 */
export async function writeIdentityManifest(
	deliverablesPath: string,
	manifest: IdentityManifest,
): Promise<string> {
	await fs.ensureDir(deliverablesPath);
	const file = path.join(deliverablesPath, SCAN_IDENTITIES_FILE);
	await fs.writeFile(file, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
	return file;
}
