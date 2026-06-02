// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
