// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { executeGitCommandWithRetry } from "../command.js";
import {
	type GitOperationResult,
	logChangeSummary,
	toErrorResult,
} from "../internal.js";
import { getChangedFiles, isGitRepository } from "../repository.js";

export async function commitGitSuccess(
	sourceDir: string,
	description: string,
	logger: ActivityLogger,
): Promise<GitOperationResult> {
	// Skip git operations if not a git repository
	if (!(await isGitRepository(sourceDir))) {
		logger.info("Skipping git commit (not a git repository)");
		return { success: true };
	}

	logger.info(`Committing successful results for ${description}`);
	try {
		const changes = await getChangedFiles(
			sourceDir,
			"status check for success commit",
		);

		await executeGitCommandWithRetry(
			["git", "add", "-A"],
			sourceDir,
			"staging changes for success commit",
		);
		await executeGitCommandWithRetry(
			[
				"git",
				"commit",
				"-m",
				`✅ ${description}: completed successfully`,
				"--allow-empty",
			],
			sourceDir,
			"creating success commit",
		);

		logChangeSummary(
			changes,
			"Success commit created with {count} file changes:",
			"Empty success commit created (agent made no file changes)",
			logger,
		);
		return { success: true };
	} catch (error) {
		const result = toErrorResult(error);
		logger.warn(
			`Success commit failed after retries: ${result.error?.message}`,
		);
		return result;
	}
}
