// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { PentestError } from "../../services/error-handling.js";
import type { Rule } from "../../types/config.js";
import { ErrorCode } from "../../types/errors.js";

export const checkForDuplicates = (rules: Rule[], ruleType: string): void => {
	const seen = new Set<string>();
	rules.forEach((rule, index) => {
		const key = `${rule.type}:${rule.url_path}`;
		if (seen.has(key)) {
			throw new PentestError(
				`Duplicate rule found in rules.${ruleType}[${index}]: ${rule.type} '${rule.url_path}'`,
				"config",
				false,
				{
					field: `rules.${ruleType}[${index}]`,
					ruleType: rule.type,
					urlPath: rule.url_path,
				},
				ErrorCode.CONFIG_VALIDATION_FAILED,
			);
		}
		seen.add(key);
	});
};

export const checkForConflicts = (
	avoidRules: Rule[] = [],
	focusRules: Rule[] = [],
): void => {
	const avoidSet = new Set(
		avoidRules.map((rule) => `${rule.type}:${rule.url_path}`),
	);

	focusRules.forEach((rule, index) => {
		const key = `${rule.type}:${rule.url_path}`;
		if (avoidSet.has(key)) {
			throw new PentestError(
				`Conflicting rule found: rules.focus[${index}] '${rule.url_path}' also exists in rules.avoid`,
				"config",
				false,
				{ field: `rules.focus[${index}]`, urlPath: rule.url_path },
				ErrorCode.CONFIG_VALIDATION_FAILED,
			);
		}
	});
};
