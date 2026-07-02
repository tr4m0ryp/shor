// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { ErrorCode } from "../../../types/errors.js";
import { PentestError } from "../../error-handling.js";
import { executeGitCommandWithRetry } from "../command.js";
import { type GitOperationResult, logChangeSummary } from "../internal.js";
import { getChangedFiles, isGitRepository } from "../repository.js";

// Two-phase reset: hard reset (tracked files) + clean (untracked files).
export async function rollbackGitWorkspace(
	sourceDir: string,
	reason: string = "retry preparation",
	logger: ActivityLogger,
): Promise<GitOperationResult> {
	// Skip git operations if not a git repository
	if (!(await isGitRepository(sourceDir))) {
		logger.info("Skipping git rollback (not a git repository)");
		return { success: true };
	}

	logger.info(`Rolling back workspace for ${reason}`);
	try {
		const changes = await getChangedFiles(
			sourceDir,
			"status check for rollback",
		);

		await executeGitCommandWithRetry(
			["git", "reset", "--hard", "HEAD"],
			sourceDir,
			"hard reset for rollback",
		);
		await executeGitCommandWithRetry(
			["git", "clean", "-fd"],
			sourceDir,
			"cleaning untracked files for rollback",
		);

		logChangeSummary(
			changes,
			"Rollback completed - removed {count} contaminated changes:",
			"Rollback completed - no changes to remove",
			logger,
			"info",
			3,
		);
		return { success: true };
	} catch (error) {
		const errMsg = error instanceof Error ? error.message : String(error);
		logger.error(`Rollback failed after retries: ${errMsg}`);
		return {
			success: false,
			error: new PentestError(
				`Git rollback failed: ${errMsg}`,
				"filesystem",
				false, // Non-retryable - rollback is best-effort cleanup
				{ sourceDir, reason },
				ErrorCode.GIT_ROLLBACK_FAILED,
			),
		};
	}
}
