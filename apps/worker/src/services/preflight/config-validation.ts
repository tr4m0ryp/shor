// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Configuration file preflight validation.
 *
 * Parses the YAML config and runs JSON Schema validation through the
 * shared config parser, catching schema errors before any agent runs.
 */

import { parseConfig } from "../../config-parser.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { ErrorCode } from "../../types/errors.js";
import { err, ok, type Result } from "../../types/result.js";
import { PentestError } from "../error-handling.js";

export async function validateConfig(
	configPath: string,
	logger: ActivityLogger,
): Promise<Result<void, PentestError>> {
	logger.info("Validating configuration file...", { configPath });

	try {
		await parseConfig(configPath);
		logger.info("Configuration file OK");
		return ok(undefined);
	} catch (error) {
		if (error instanceof PentestError) {
			return err(error);
		}
		const message = error instanceof Error ? error.message : String(error);
		return err(
			new PentestError(
				`Configuration validation failed: ${message}`,
				"config",
				false,
				{ configPath },
				ErrorCode.CONFIG_VALIDATION_FAILED,
			),
		);
	}
}
