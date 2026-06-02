// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs } from "zx";
import { PentestError } from "../../error-handling.js";
import type {
	PathsWithError,
	PathsWithExistence,
	PathsWithQueue,
	QueueData,
	QueueValidationResult,
} from "../types.js";

// Pure function to validate queue structure.
function validateQueueStructure(content: string): QueueValidationResult {
	try {
		const parsed = JSON.parse(content) as unknown;
		const isValid =
			typeof parsed === "object" &&
			parsed !== null &&
			"vulnerabilities" in parsed &&
			Array.isArray((parsed as QueueData).vulnerabilities);

		return Object.freeze({
			valid: isValid,
			data: isValid ? (parsed as QueueData) : null,
			error: null,
		});
	} catch (parseError) {
		return Object.freeze({
			valid: false,
			data: null,
			error:
				parseError instanceof Error ? parseError.message : String(parseError),
		});
	}
}

// Queue parse failures are retryable - agent can fix malformed JSON on retry.
export const validateQueueContent = async (
	pathsWithExistence: PathsWithExistence | PathsWithError,
): Promise<PathsWithQueue | PathsWithError> => {
	if ("error" in pathsWithExistence) return pathsWithExistence;

	try {
		const queueContent = await fs.readFile(pathsWithExistence.queue, "utf8");
		const queueValidation = validateQueueStructure(queueContent);

		if (!queueValidation.valid) {
			// Rule 6: Both exist, queue invalid
			return {
				error: new PentestError(
					queueValidation.error
						? `Queue validation failed for ${pathsWithExistence.vulnType}: Invalid JSON structure. Analysis agent must fix queue format.`
						: `Queue validation failed for ${pathsWithExistence.vulnType}: Missing or invalid 'vulnerabilities' array. Analysis agent must fix queue structure.`,
					"validation",
					true, // retryable
					{
						vulnType: pathsWithExistence.vulnType,
						queuePath: pathsWithExistence.queue,
						originalError: queueValidation.error,
						queueStructure: queueValidation.data
							? Object.keys(queueValidation.data)
							: [],
					},
				),
			};
		}

		return Object.freeze({
			...pathsWithExistence,
			queueData: queueValidation.data as QueueData,
		});
	} catch (readError) {
		return {
			error: new PentestError(
				`Failed to read queue file for ${pathsWithExistence.vulnType}: ${readError instanceof Error ? readError.message : String(readError)}`,
				"filesystem",
				false,
				{
					vulnType: pathsWithExistence.vulnType,
					queuePath: pathsWithExistence.queue,
					originalError:
						readError instanceof Error ? readError.message : String(readError),
				},
			),
		};
	}
};
