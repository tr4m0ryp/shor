// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Repository preflight validation.
 *
 * Verifies the repo path exists, is a directory, and contains a `.git`
 * directory (unless the consumer has already stripped it after clone).
 */

import fs from "node:fs/promises";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { ErrorCode } from "../../types/errors.js";
import { err, ok, type Result } from "../../types/result.js";
import { PentestError } from "../error-handling.js";

export async function validateRepo(
	repoPath: string,
	logger: ActivityLogger,
	skipGitCheck?: boolean,
): Promise<Result<void, PentestError>> {
	logger.info("Checking repository path...", { repoPath });

	// 1. Check repo directory exists
	try {
		const stats = await fs.stat(repoPath);
		if (!stats.isDirectory()) {
			return err(
				new PentestError(
					`Repository path is not a directory: ${repoPath}`,
					"config",
					false,
					{ repoPath },
					ErrorCode.REPO_NOT_FOUND,
				),
			);
		}
	} catch {
		return err(
			new PentestError(
				`Repository path does not exist: ${repoPath}`,
				"config",
				false,
				{ repoPath },
				ErrorCode.REPO_NOT_FOUND,
			),
		);
	}

	// 2. Check .git directory exists (skipped when consumer removes .git after clone)
	if (!skipGitCheck) {
		try {
			const gitStats = await fs.stat(`${repoPath}/.git`);
			if (!gitStats.isDirectory()) {
				return err(
					new PentestError(
						`Not a git repository (no .git directory): ${repoPath}`,
						"config",
						false,
						{ repoPath },
						ErrorCode.REPO_NOT_FOUND,
					),
				);
			}
		} catch {
			return err(
				new PentestError(
					`Not a git repository (no .git directory): ${repoPath}`,
					"config",
					false,
					{ repoPath },
					ErrorCode.REPO_NOT_FOUND,
				),
			);
		}
	} else {
		logger.info("Skipping .git check (skipGitCheck enabled)");
	}

	logger.info("Repository path OK");
	return ok(undefined);
}
