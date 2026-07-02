// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Resolve the ordered identity set from the (already sanitized/validated) auth
 * config. The PRIMARY identity is always derived from the top-level credentials
 * (the single-identity default that has always existed); every entry in
 * `authentication.identities` becomes an additional secondary identity.
 *
 * CRITICAL (ADR-050): a {@link ResolvedIdentity} carries ONLY non-secret
 * metadata — label, role, isPrimary, and the credential-free session label. The
 * credential material on the source config is deliberately NOT copied here, so
 * nothing downstream of this function (manifest, storage-state seam) can ever
 * surface a username/password/secret.
 */

import {
	identitySessionLabel,
	type IdentitySessionLabel,
} from "../../session-manager.js";
import type { Authentication } from "../../types/config.js";

/** Stable, non-secret label for the primary (top-level credentials) identity. */
export const PRIMARY_IDENTITY_LABEL = "primary";

/** Non-secret, prompt-safe view of one identity — never holds credentials. */
export interface ResolvedIdentity {
	readonly label: string;
	readonly role?: string;
	readonly isPrimary: boolean;
	readonly sessionLabel: IdentitySessionLabel;
}

/** Allocate a session label unique within `seen`, suffixing on collision. */
function uniqueSessionLabel(
	base: IdentitySessionLabel,
	seen: Set<string>,
): IdentitySessionLabel {
	if (!seen.has(base)) {
		seen.add(base);
		return base;
	}
	for (let n = 2; n < 1000; n++) {
		const candidate = `${base}-${n}` as IdentitySessionLabel;
		if (!seen.has(candidate)) {
			seen.add(candidate);
			return candidate;
		}
	}
	const fallback = `${base}-${seen.size}` as IdentitySessionLabel;
	seen.add(fallback);
	return fallback;
}

/**
 * Build the ordered identity list: primary first, then each configured secondary
 * (in declaration order). Returns `[]` when no authentication is configured
 * (black-box / unauthenticated scan) so callers degrade cleanly. Labels/roles
 * are passed through verbatim from the validated config; only the credential-free
 * session label is synthesized here.
 */
export function collectIdentities(
	auth: Authentication | null | undefined,
): ResolvedIdentity[] {
	if (!auth) return [];

	const seen = new Set<string>();
	const primary: ResolvedIdentity = {
		label: PRIMARY_IDENTITY_LABEL,
		isPrimary: true,
		sessionLabel: uniqueSessionLabel(
			identitySessionLabel(PRIMARY_IDENTITY_LABEL),
			seen,
		),
	};
	const result: ResolvedIdentity[] = [primary];

	auth.identities?.forEach((identity, index) => {
		const trimmed = identity.label?.trim();
		const label = trimmed && trimmed.length > 0 ? trimmed : `identity-${index + 1}`;
		const role = identity.role?.trim();
		const sessionLabel = uniqueSessionLabel(identitySessionLabel(label), seen);
		result.push({
			label,
			isPrimary: false,
			sessionLabel,
			...(role && { role }),
		});
	});

	return result;
}
