// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { PentestError } from "../../services/error-handling.js";
import type { Config } from "../../types/config.js";
import { ErrorCode } from "../../types/errors.js";
import { formatAjvErrors, validateSchema } from "../schema-validation.js";
import { performSecurityValidation } from "./security.js";

export const validateConfig = (config: Config): void => {
	if (!config || typeof config !== "object") {
		throw new PentestError(
			"Configuration must be a valid object",
			"config",
			false,
			{},
			ErrorCode.CONFIG_VALIDATION_FAILED,
		);
	}

	if (Array.isArray(config)) {
		throw new PentestError(
			"Configuration must be an object, not an array",
			"config",
			false,
			{},
			ErrorCode.CONFIG_VALIDATION_FAILED,
		);
	}

	const isValid = validateSchema(config);
	if (!isValid) {
		const errors = validateSchema.errors || [];
		const errorMessages = formatAjvErrors(errors);
		throw new PentestError(
			`Configuration validation failed:\n  - ${errorMessages.join("\n  - ")}`,
			"config",
			false,
			{ validationErrors: errorMessages },
			ErrorCode.CONFIG_VALIDATION_FAILED,
		);
	}

	performSecurityValidation(config);

	if (!config.rules && !config.authentication && !config.description) {
		console.warn(
			"⚠️  Configuration file contains no rules, authentication, or description. The pentest will run without any scoping restrictions or login capabilities.",
		);
	} else if (config.rules && !config.rules.avoid && !config.rules.focus) {
		console.warn(
			"⚠️  Configuration file contains no rules. The pentest will run without any scoping restrictions.",
		);
	}
};
