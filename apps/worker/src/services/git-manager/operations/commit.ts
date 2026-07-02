// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
