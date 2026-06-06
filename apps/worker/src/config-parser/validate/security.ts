// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { PentestError } from "../../services/error-handling.js";
import type { Config, Identity, Rule } from "../../types/config.js";
import { ErrorCode } from "../../types/errors.js";
import { checkForConflicts, checkForDuplicates } from "./duplicates.js";
import { validateRuleTypeSpecific } from "./rule-types.js";

export const DANGEROUS_PATTERNS: RegExp[] = [
	/\.\.\//, // Path traversal
	/[<>]/, // HTML/XML injection
	/javascript:/i, // JavaScript URLs
	/data:/i, // Data URLs
	/file:/i, // File URLs
];

export const performSecurityValidation = (config: Config): void => {
	if (config.authentication) {
		const auth = config.authentication;

		// Check login_url for dangerous patterns (AJV's "uri" format allows javascript: per RFC 3986)
		if (auth.login_url) {
			for (const pattern of DANGEROUS_PATTERNS) {
				if (pattern.test(auth.login_url)) {
					throw new PentestError(
						`authentication.login_url contains potentially dangerous pattern: ${pattern.source}`,
						"config",
						false,
						{ field: "login_url", pattern: pattern.source },
						ErrorCode.CONFIG_VALIDATION_FAILED,
					);
				}
			}
		}

		if (auth.credentials) {
			for (const pattern of DANGEROUS_PATTERNS) {
				if (pattern.test(auth.credentials.username)) {
					throw new PentestError(
						`authentication.credentials.username contains potentially dangerous pattern: ${pattern.source}`,
						"config",
						false,
						{ field: "credentials.username", pattern: pattern.source },
						ErrorCode.CONFIG_VALIDATION_FAILED,
					);
				}
				if (pattern.test(auth.credentials.password)) {
					throw new PentestError(
						`authentication.credentials.password contains potentially dangerous pattern: ${pattern.source}`,
						"config",
						false,
						{ field: "credentials.password", pattern: pattern.source },
						ErrorCode.CONFIG_VALIDATION_FAILED,
					);
				}
			}
		}

		if (auth.login_flow) {
			auth.login_flow.forEach((step, index) => {
				for (const pattern of DANGEROUS_PATTERNS) {
					if (pattern.test(step)) {
						throw new PentestError(
							`authentication.login_flow[${index}] contains potentially dangerous pattern: ${pattern.source}`,
							"config",
							false,
							{ field: `login_flow[${index}]`, pattern: pattern.source },
							ErrorCode.CONFIG_VALIDATION_FAILED,
						);
					}
				}
			});
		}

		// Secondary identities (task 008): the same dangerous-pattern gate the
		// primary credentials pass — so a malicious label/role/credential can never
		// ride in through the multi-identity path.
		if (auth.identities) {
			auth.identities.forEach((identity, index) =>
				validateIdentitySecurity(identity, index),
			);
		}
	}

	if (config.rules) {
		validateRulesSecurity(config.rules.avoid, "avoid");
		validateRulesSecurity(config.rules.focus, "focus");

		checkForDuplicates(config.rules.avoid || [], "avoid");
		checkForDuplicates(config.rules.focus || [], "focus");
		checkForConflicts(config.rules.avoid, config.rules.focus);
	}

	if (config.description) {
		for (const pattern of DANGEROUS_PATTERNS) {
			if (pattern.test(config.description)) {
				throw new PentestError(
					`description contains potentially dangerous pattern: ${pattern.source}`,
					"config",
					false,
					{ field: "description", pattern: pattern.source },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
		}
	}
};

/**
 * Run the dangerous-pattern gate over one secondary identity's non-secret
 * metadata (label/role) and its credentials. Field paths mirror the AJV/primary
 * messages so an operator sees exactly which identity tripped the gate.
 */
export const validateIdentitySecurity = (
	identity: Identity,
	index: number,
): void => {
	const checks: Array<[string, string | undefined]> = [
		["label", identity.label],
		["role", identity.role],
		["credentials.username", identity.credentials?.username],
		["credentials.password", identity.credentials?.password],
		["success_condition.value", identity.success_condition?.value],
	];
	for (const [field, value] of checks) {
		if (value === undefined) continue;
		for (const pattern of DANGEROUS_PATTERNS) {
			if (pattern.test(value)) {
				throw new PentestError(
					`authentication.identities[${index}].${field} contains potentially dangerous pattern: ${pattern.source}`,
					"config",
					false,
					{
						field: `identities[${index}].${field}`,
						pattern: pattern.source,
					},
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
		}
	}
};

export const validateRulesSecurity = (
	rules: Rule[] | undefined,
	ruleType: string,
): void => {
	if (!rules) return;

	rules.forEach((rule, index) => {
		for (const pattern of DANGEROUS_PATTERNS) {
			if (pattern.test(rule.url_path)) {
				throw new PentestError(
					`rules.${ruleType}[${index}].url_path contains potentially dangerous pattern: ${pattern.source}`,
					"config",
					false,
					{
						field: `rules.${ruleType}[${index}].url_path`,
						pattern: pattern.source,
					},
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			if (pattern.test(rule.description)) {
				throw new PentestError(
					`rules.${ruleType}[${index}].description contains potentially dangerous pattern: ${pattern.source}`,
					"config",
					false,
					{
						field: `rules.${ruleType}[${index}].description`,
						pattern: pattern.source,
					},
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
		}

		validateRuleTypeSpecific(rule, ruleType, index);
	});
};
