// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type {
	Authentication,
	Credentials,
	Identity,
	Rule,
	SuccessCondition,
} from "../types/config.js";

export const sanitizeRule = (rule: Rule): Rule => {
	return {
		description: rule.description.trim(),
		type: rule.type.toLowerCase().trim() as Rule["type"],
		url_path: rule.url_path.trim(),
	};
};

/** Trim identifying material but NEVER mutate the secret password body. */
const sanitizeCredentials = (credentials: Credentials): Credentials => ({
	username: credentials.username.trim(),
	password: credentials.password,
	...(credentials.totp_secret && {
		totp_secret: credentials.totp_secret.trim(),
	}),
});

const sanitizeSuccessCondition = (
	condition: SuccessCondition,
): SuccessCondition => ({
	type: condition.type.toLowerCase().trim() as SuccessCondition["type"],
	value: condition.value.trim(),
});

/**
 * Sanitize a secondary identity (task 008). Mirrors the primary auth handling:
 * trim the non-secret label/role and credential username, leave the password
 * body untouched. Threaded through so multi-identity is never silently dropped.
 */
export const sanitizeIdentity = (identity: Identity): Identity => ({
	label: identity.label.trim(),
	...(identity.role && { role: identity.role.trim() }),
	credentials: sanitizeCredentials(identity.credentials),
	...(identity.success_condition && {
		success_condition: sanitizeSuccessCondition(identity.success_condition),
	}),
});

export const sanitizeAuthentication = (
	auth: Authentication,
): Authentication => {
	return {
		login_type: auth.login_type
			.toLowerCase()
			.trim() as Authentication["login_type"],
		login_url: auth.login_url.trim(),
		credentials: sanitizeCredentials(auth.credentials),
		...(auth.login_flow && {
			login_flow: auth.login_flow.map((step) => step.trim()),
		}),
		success_condition: sanitizeSuccessCondition(auth.success_condition),
		...(auth.identities && {
			identities: auth.identities.map(sanitizeIdentity),
		}),
	};
};
