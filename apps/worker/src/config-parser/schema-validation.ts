// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { createRequire } from "node:module";
import { Ajv, type ErrorObject, type ValidateFunction } from "ajv";
import type { FormatsPlugin } from "ajv-formats";
import { fs } from "zx";
import { PentestError } from "../services/error-handling.js";

// Handle ESM/CJS interop for ajv-formats using require
const require = createRequire(import.meta.url);
const addFormats: FormatsPlugin = require("ajv-formats");

const ajv = new Ajv({ allErrors: true, verbose: true });
addFormats(ajv);

let configSchema: object;
export let validateSchema: ValidateFunction;

try {
	const schemaPath = new URL(
		"../../configs/config-schema.json",
		import.meta.url,
	);
	const schemaContent = await fs.readFile(schemaPath, "utf8");
	configSchema = JSON.parse(schemaContent) as object;
	validateSchema = ajv.compile(configSchema);
} catch (error) {
	const errMsg = error instanceof Error ? error.message : String(error);
	throw new PentestError(
		`Failed to load configuration schema: ${errMsg}`,
		"config",
		false,
		{
			schemaPath: "../../configs/config-schema.json",
			originalError: errMsg,
		},
	);
}

/**
 * Format a single AJV error into a human-readable message.
 * Translates AJV error keywords into plain English descriptions.
 */
export function formatAjvError(error: ErrorObject): string {
	const path = error.instancePath || "root";
	const params = error.params as Record<string, unknown>;

	switch (error.keyword) {
		case "required": {
			const missingProperty = params.missingProperty as string;
			return `Missing required field: "${missingProperty}" at ${path || "root"}`;
		}

		case "type": {
			const expectedType = params.type as string;
			return `Invalid type at ${path}: expected ${expectedType}`;
		}

		case "enum": {
			const allowedValues = params.allowedValues as unknown[];
			const formattedValues = allowedValues.map((v) => `"${v}"`).join(", ");
			return `Invalid value at ${path}: must be one of [${formattedValues}]`;
		}

		case "additionalProperties": {
			const additionalProperty = params.additionalProperty as string;
			return `Unknown field at ${path}: "${additionalProperty}" is not allowed`;
		}

		case "minLength": {
			const limit = params.limit as number;
			return `Value at ${path} is too short: must have at least ${limit} character(s)`;
		}

		case "maxLength": {
			const limit = params.limit as number;
			return `Value at ${path} is too long: must have at most ${limit} character(s)`;
		}

		case "minimum": {
			const limit = params.limit as number;
			return `Value at ${path} is too small: must be >= ${limit}`;
		}

		case "maximum": {
			const limit = params.limit as number;
			return `Value at ${path} is too large: must be <= ${limit}`;
		}

		case "minItems": {
			const limit = params.limit as number;
			return `Array at ${path} has too few items: must have at least ${limit} item(s)`;
		}

		case "maxItems": {
			const limit = params.limit as number;
			return `Array at ${path} has too many items: must have at most ${limit} item(s)`;
		}

		case "pattern": {
			const pattern = params.pattern as string;
			return `Value at ${path} does not match required pattern: ${pattern}`;
		}

		case "format": {
			const format = params.format as string;
			return `Value at ${path} must be a valid ${format}`;
		}

		case "const": {
			const allowedValue = params.allowedValue as unknown;
			return `Value at ${path} must be exactly "${allowedValue}"`;
		}

		case "oneOf": {
			return `Value at ${path} must match exactly one schema (matched ${params.passingSchemas ?? 0})`;
		}

		case "anyOf": {
			return `Value at ${path} must match at least one of the allowed schemas`;
		}

		case "not": {
			return `Value at ${path} matches a schema it should not match`;
		}

		case "if": {
			return `Value at ${path} does not satisfy conditional schema requirements`;
		}

		case "uniqueItems": {
			const i = params.i as number;
			const j = params.j as number;
			return `Array at ${path} contains duplicate items at positions ${j} and ${i}`;
		}

		case "propertyNames": {
			const propertyName = params.propertyName as string;
			return `Invalid property name at ${path}: "${propertyName}" does not match naming requirements`;
		}

		case "dependencies":
		case "dependentRequired": {
			const property = params.property as string;
			const missingProperty = params.missingProperty as string;
			return `Missing dependent field at ${path}: "${missingProperty}" is required when "${property}" is present`;
		}

		default: {
			// Fallback for any unhandled keywords - use AJV's message if available
			const message =
				error.message || `validation failed for keyword "${error.keyword}"`;
			return `${path}: ${message}`;
		}
	}
}

/**
 * Format all AJV errors into a list of human-readable messages.
 * Returns an array of formatted error strings.
 */
export function formatAjvErrors(errors: ErrorObject[]): string[] {
	return errors.map(formatAjvError);
}
