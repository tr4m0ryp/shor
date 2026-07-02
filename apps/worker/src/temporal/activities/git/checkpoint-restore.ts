// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Git checkpoint helpers for resuming workspaces.
 *
 * Both the resume loader and the workflow restore path share
 * `findLatestCommit`, so it lives here alongside the public restore.
 */

import fs from "node:fs/promises";
import path from "node:path";
import { deliverablesDir } from "../../../paths.js";
import { PentestError } from "../../../services/error-handling.js";
import { executeGitCommandWithRetry } from "../../../services/git-manager.js";
import { AGENTS } from "../../../session-manager.js";
import type { AgentName } from "../../../types/agents.js";
import { ErrorCode } from "../../../types/errors.js";
import { fileExists } from "../../../utils/file-io.js";
import { createActivityLogger } from "../../activity-logger.js";

/**
 * Resolve the most recent commit hash from a set of candidates.
 *
 * Single-hash inputs short-circuit; multi-hash inputs defer to
 * `git rev-list --max-count=1` to pick the topologically newest.
 */
export async function findLatestCommit(
	gitDir: string,
	commitHashes: string[],
): Promise<string> {
	if (commitHashes.length === 1) {
		const hash = commitHashes[0];
		if (!hash) {
			throw new PentestError(
				"Empty commit hash in array",
				"filesystem",
				false, // Non-retryable - corrupt workspace state
				{ phase: "resume" },
				ErrorCode.GIT_CHECKPOINT_FAILED,
			);
		}
		return hash;
	}

	const result = await executeGitCommandWithRetry(
		["git", "rev-list", "--max-count=1", ...commitHashes],
		gitDir,
		"find latest commit",
	);

	return result.stdout.trim();
}

/**
 * Restore deliverables git to a checkpoint.
 * Operates on the private git inside workspace deliverables, not the user's repo.
 */
export async function restoreGitCheckpoint(
	repoPath: string,
	checkpointHash: string,
	incompleteAgents: AgentName[],
	deliverablesSubdir?: string,
): Promise<void> {
	const deliverablesPath = deliverablesDir(repoPath, deliverablesSubdir);
	const logger = createActivityLogger();
	logger.info(`Restoring deliverables to ${checkpointHash}...`);

	await executeGitCommandWithRetry(
		["git", "reset", "--hard", checkpointHash],
		deliverablesPath,
		"reset deliverables to checkpoint",
	);
	await executeGitCommandWithRetry(
		["git", "clean", "-fd"],
		deliverablesPath,
		"clean untracked deliverables",
	);

	// Explicitly delete partial deliverables for incomplete agents
	for (const agentName of incompleteAgents) {
		const deliverableFilename = AGENTS[agentName].deliverableFilename;
		const deliverablePath = path.join(deliverablesPath, deliverableFilename);
		try {
			const exists = await fileExists(deliverablePath);
			if (exists) {
				logger.warn(`Cleaning partial deliverable: ${agentName}`);
				await fs.unlink(deliverablePath);
			}
		} catch (error) {
			logger.info(`Note: Failed to delete ${deliverablePath}: ${error}`);
		}
	}

	logger.info("Deliverables restored to clean state");
}
