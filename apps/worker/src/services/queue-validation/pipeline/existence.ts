// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { fs } from "zx";
import { ErrorCode } from "../../../types/errors.js";
import { PentestError } from "../../error-handling.js";
import { fileExistenceRules } from "../rules.js";
import type {
	PathsBase,
	PathsWithError,
	PathsWithExistence,
} from "../types.js";

// Check whether the deliverable + queue files exist on disk.
export const checkFileExistence = async (
	paths: PathsBase | PathsWithError,
): Promise<PathsWithExistence | PathsWithError> => {
	if ("error" in paths) return paths;

	const [deliverableExists, queueExists] = await Promise.all([
		fs.pathExists(paths.deliverable),
		fs.pathExists(paths.queue),
	]);

	return Object.freeze({
		...paths,
		existence: Object.freeze({ deliverableExists, queueExists }),
	});
};

// Validates deliverable/queue symmetry - both must exist or neither.
export const validateExistenceRules = (
	pathsWithExistence: PathsWithExistence | PathsWithError,
): PathsWithExistence | PathsWithError => {
	if ("error" in pathsWithExistence) return pathsWithExistence;

	const { existence, vulnType } = pathsWithExistence;

	// Find the first rule that fails
	const failedRule = fileExistenceRules.find(
		(rule) => !rule.predicate(existence),
	);

	if (failedRule) {
		const message =
			typeof failedRule.errorMessage === "function"
				? failedRule.errorMessage(existence)
				: failedRule.errorMessage;

		return {
			error: new PentestError(
				`${message} (${vulnType})`,
				"validation",
				failedRule.retryable,
				{
					vulnType,
					deliverablePath: pathsWithExistence.deliverable,
					queuePath: pathsWithExistence.queue,
					existence,
				},
				ErrorCode.DELIVERABLE_NOT_FOUND,
			),
		};
	}

	return pathsWithExistence;
};
