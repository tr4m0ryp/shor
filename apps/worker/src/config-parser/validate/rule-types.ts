// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { PentestError } from "../../services/error-handling.js";
import type { Rule } from "../../types/config.js";
import { ErrorCode } from "../../types/errors.js";

export const validateRuleTypeSpecific = (
	rule: Rule,
	ruleType: string,
	index: number,
): void => {
	const field = `rules.${ruleType}[${index}].url_path`;

	switch (rule.type) {
		case "path":
			if (!rule.url_path.startsWith("/")) {
				throw new PentestError(
					`${field} for type 'path' must start with '/'`,
					"config",
					false,
					{ field, ruleType: rule.type },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			break;

		case "subdomain":
		case "domain":
			// Basic domain validation - no slashes allowed
			if (rule.url_path.includes("/")) {
				throw new PentestError(
					`${field} for type '${rule.type}' cannot contain '/' characters`,
					"config",
					false,
					{ field, ruleType: rule.type },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			// Must contain at least one dot for domains
			if (rule.type === "domain" && !rule.url_path.includes(".")) {
				throw new PentestError(
					`${field} for type 'domain' must be a valid domain name`,
					"config",
					false,
					{ field, ruleType: rule.type },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			break;

		case "method": {
			const allowedMethods = [
				"GET",
				"POST",
				"PUT",
				"DELETE",
				"PATCH",
				"HEAD",
				"OPTIONS",
			];
			if (!allowedMethods.includes(rule.url_path.toUpperCase())) {
				throw new PentestError(
					`${field} for type 'method' must be one of: ${allowedMethods.join(", ")}`,
					"config",
					false,
					{ field, ruleType: rule.type, allowedMethods },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			break;
		}

		case "header":
			if (!rule.url_path.match(/^[a-zA-Z0-9\-_]+$/)) {
				throw new PentestError(
					`${field} for type 'header' must be a valid header name (alphanumeric, hyphens, underscores only)`,
					"config",
					false,
					{ field, ruleType: rule.type },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			break;

		case "parameter":
			if (!rule.url_path.match(/^[a-zA-Z0-9\-_]+$/)) {
				throw new PentestError(
					`${field} for type 'parameter' must be a valid parameter name (alphanumeric, hyphens, underscores only)`,
					"config",
					false,
					{ field, ruleType: rule.type },
					ErrorCode.CONFIG_VALIDATION_FAILED,
				);
			}
			break;
	}
};
