// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
