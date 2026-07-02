// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { DistributedConfig } from "../../types/config.js";

/**
 * The neutral sentinel `applyPromptContext` substitutes for an absent identity
 * set. `context.identities` never carries it (it stays unset instead), but guard
 * against it so `{{AUTH_CONTEXT}}` never echoes the placeholder fallback.
 */
const IDENTITY_NONE = "(none)";

/**
 * Render the `{{AUTH_CONTEXT}}` block: the per-scan FACTUAL auth metadata the
 * static `shared/_auth-scaffolding.txt` include cannot carry (login type, login
 * URL, MFA flag, credential presence, and the provisioned identity labels/roles),
 * followed by a CONCISE reminder that the harness-injected access is scaffolding
 * and the application's own auth is the test surface.
 *
 * The full subject-vs-mechanism framing — the SUBJECT/MECHANISM/IDENTITIES rules
 * and the "do not over-correct" rail — lives ONLY in the auth-scaffolding block;
 * the reminder here defers to it rather than restating it, so the two surfaces
 * cannot drift. ADR-050: labels/roles and presence flags ONLY, NEVER a credential
 * value — the runtime injects secrets out-of-band via the {{SHOR_LOGIN_*}} seam.
 *
 * @param config Per-scan distributed config (auth metadata source).
 * @param identities Pre-rendered identity labels/roles — the SAME string that
 *   fills `{{IDENTITIES}}`, emitted label/role-only by the threat-model identity
 *   renderer. Fed from the same seam so the two surfaces stay consistent. Absent
 *   or the `(none)` sentinel -> no identity list is shown.
 */
export function buildAuthContext(
	config: DistributedConfig | null,
	identities?: string,
): string {
	if (!config?.authentication) {
		return "No authentication configured - unauthenticated testing only";
	}

	const auth = config.authentication;
	// ADR-050: presence/metadata only — never the plaintext username, password,
	// or TOTP secret. The runtime resolves the actual material out-of-band via the
	// {{SHOR_LOGIN_*}} seam tokens; here we report only THAT a credential exists.
	const lines = [
		`- Login type: ${auth.login_type.toUpperCase()}`,
		`- Login URL: ${auth.login_url}`,
		`- Credentials: ${auth.credentials?.username ? "configured (injected at runtime)" : "not configured"}`,
		`- MFA: ${auth.credentials?.totp_secret ? "TOTP enabled" : "none configured"}`,
	];

	// Identity-aware: when the scan provisioned a labelled identity set, list each
	// one (labels + roles only). Multiple identities each get a line. This reuses
	// the exact string the {{IDENTITIES}} slot carries, so the metadata snapshot
	// here and the framing in the auth-scaffolding block can never disagree.
	const identityList = identities?.trim();
	if (identityList && identityList !== IDENTITY_NONE) {
		lines.push("- Provisioned identities (labels/roles only):");
		for (const entry of identityList.split("\n")) {
			lines.push(`  ${entry.trim()}`);
		}
	}

	// CONCISE reminder, consistent with and explicitly DEFERRING to the canonical
	// auth-scaffolding block — not a second copy of its rules (avoids drift). It is
	// NOT a blunt "ignore auth" line: the injected credentials are the off-limits
	// subject; the app's own auth and the provisioned identities remain in scope.
	lines.push(
		"",
		"Reminder: the injected credentials and login above are HARNESS SCAFFOLDING — a means of access, never a finding; the application's OWN authentication and authorization are the test surface (use the provisioned identities as authorization-testing instruments).",
		"The full scaffolding and test-surface rules are stated in the auth-scaffolding block.",
	);

	return lines.join("\n");
}
