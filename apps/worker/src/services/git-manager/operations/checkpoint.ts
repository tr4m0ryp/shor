// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { executeGitCommandWithRetry } from "../command.js";
import { type GitOperationResult, toErrorResult } from "../internal.js";
import { getChangedFiles, isGitRepository } from "../repository.js";
import { rollbackGitWorkspace } from "./rollback.js";

// Creates checkpoint before each attempt. First attempt preserves workspace; retries clean it.
export async function createGitCheckpoint(
	sourceDir: string,
	description: string,
	attempt: number,
	logger: ActivityLogger,
): Promise<GitOperationResult> {
	// Skip git operations if not a git repository
	if (!(await isGitRepository(sourceDir))) {
		logger.info("Skipping git checkpoint (not a git repository)");
		return { success: true };
	}

	logger.info(`Creating checkpoint for ${description} (attempt ${attempt})`);
	try {
		// 1. On retries, clean workspace to prevent pollution from previous attempt
		if (attempt > 1) {
			const cleanResult = await rollbackGitWorkspace(
				sourceDir,
				`${description} (retry cleanup)`,
				logger,
			);
			if (!cleanResult.success) {
				logger.warn(
					`Workspace cleanup failed, continuing anyway: ${cleanResult.error?.message}`,
				);
			}
		}

		// 2. Detect existing changes
		const changes = await getChangedFiles(sourceDir, "status check");
		const hasChanges = changes.length > 0;

		// 3. Stage and commit checkpoint
		await executeGitCommandWithRetry(
			["git", "add", "-A"],
			sourceDir,
			"staging changes",
		);
		await executeGitCommandWithRetry(
			[
				"git",
				"commit",
				"-m",
				`📍 Checkpoint: ${description} (attempt ${attempt})`,
				"--allow-empty",
			],
			sourceDir,
			"creating commit",
		);

		// 4. Log result
		if (hasChanges) {
			logger.info("Checkpoint created with uncommitted changes staged");
		} else {
			logger.info("Empty checkpoint created (no workspace changes)");
		}
		return { success: true };
	} catch (error) {
		const result = toErrorResult(error);
		logger.warn(
			`Checkpoint creation failed after retries: ${result.error?.message}`,
		);
		return result;
	}
}
