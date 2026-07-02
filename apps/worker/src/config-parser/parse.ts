// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import yaml from "js-yaml";
import { fs } from "zx";
import { PentestError } from "../services/error-handling.js";
import type { Config } from "../types/config.js";
import { ErrorCode } from "../types/errors.js";
import { validateConfig } from "./validate/config.js";

export const parseConfig = async (configPath: string): Promise<Config> => {
	try {
		// 1. Verify file exists
		if (!(await fs.pathExists(configPath))) {
			throw new PentestError(
				`Configuration file not found: ${configPath}`,
				"config",
				false,
				{ configPath },
				ErrorCode.CONFIG_NOT_FOUND,
			);
		}

		// 2. Check file size
		const stats = await fs.stat(configPath);
		const maxFileSize = 1024 * 1024; // 1MB
		if (stats.size > maxFileSize) {
			throw new PentestError(
				`Configuration file too large: ${stats.size} bytes (maximum: ${maxFileSize} bytes)`,
				"config",
				false,
				{ configPath, fileSize: stats.size, maxFileSize },
				ErrorCode.CONFIG_VALIDATION_FAILED,
			);
		}

		// 3. Read and check for empty content
		const configContent = await fs.readFile(configPath, "utf8");

		if (!configContent.trim()) {
			throw new PentestError(
				"Configuration file is empty",
				"config",
				false,
				{ configPath },
				ErrorCode.CONFIG_VALIDATION_FAILED,
			);
		}

		// 4. Parse YAML with safe schema
		let config: unknown;
		try {
			config = yaml.load(configContent, {
				schema: yaml.FAILSAFE_SCHEMA, // Only basic YAML types, no JS evaluation
				json: false, // Don't allow JSON-specific syntax
				filename: configPath,
			});
		} catch (yamlError) {
			const errMsg =
				yamlError instanceof Error ? yamlError.message : String(yamlError);
			throw new PentestError(
				`YAML parsing failed: ${errMsg}`,
				"config",
				false,
				{ configPath, originalError: errMsg },
				ErrorCode.CONFIG_PARSE_ERROR,
			);
		}

		// 5. Guard against null/undefined parse result
		if (config === null || config === undefined) {
			throw new PentestError(
				"Configuration file resulted in null/undefined after parsing",
				"config",
				false,
				{ configPath },
				ErrorCode.CONFIG_PARSE_ERROR,
			);
		}

		// 6. Validate schema and security rules, then return
		validateConfig(config as Config);

		return config as Config;
	} catch (error) {
		// PentestError instances are already well-formatted, re-throw as-is
		if (error instanceof PentestError) {
			throw error;
		}
		const errMsg = error instanceof Error ? error.message : String(error);
		throw new PentestError(
			`Failed to parse configuration file '${configPath}': ${errMsg}`,
			"config",
			false,
			{ configPath, originalError: errMsg },
			ErrorCode.CONFIG_PARSE_ERROR,
		);
	}
};

/**
 * Parse a raw YAML string into a validated Config object.
 *
 * Same validation as parseConfig but accepts a string instead of a file path.
 * Used when config YAML is passed inline (e.g., from a parent workflow).
 */
export const parseConfigYAML = (yamlContent: string): Config => {
	if (!yamlContent.trim()) {
		throw new PentestError(
			"Configuration YAML string is empty",
			"config",
			false,
			{},
			ErrorCode.CONFIG_VALIDATION_FAILED,
		);
	}

	let config: unknown;
	try {
		config = yaml.load(yamlContent, {
			schema: yaml.FAILSAFE_SCHEMA,
			json: false,
		});
	} catch (yamlError) {
		const errMsg =
			yamlError instanceof Error ? yamlError.message : String(yamlError);
		throw new PentestError(
			`YAML parsing failed: ${errMsg}`,
			"config",
			false,
			{ originalError: errMsg },
			ErrorCode.CONFIG_PARSE_ERROR,
		);
	}

	if (config === null || config === undefined) {
		throw new PentestError(
			"Configuration YAML resulted in null/undefined after parsing",
			"config",
			false,
			{},
			ErrorCode.CONFIG_PARSE_ERROR,
		);
	}

	validateConfig(config as Config);
	return config as Config;
};
