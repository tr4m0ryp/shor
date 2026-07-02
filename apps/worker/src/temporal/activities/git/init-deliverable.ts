// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Initialize the private deliverables git repository.
 */

import fs from "node:fs/promises";
import path from "node:path";
import { deliverablesDir } from "../../../paths.js";
import { executeGitCommandWithRetry } from "../../../services/git-manager.js";
import type { ActivityInput } from "../types.js";

/**
 * Initialize a private git repository inside the workspace deliverables directory.
 * Idempotent — skips if .git already exists (resume case).
 */
export async function initDeliverableGit(input: ActivityInput): Promise<void> {
	const deliverablesPath = deliverablesDir(
		input.repoPath,
		input.deliverablesSubdir,
	);
	await fs.mkdir(deliverablesPath, { recursive: true });

	// Check for .git directly inside deliverables, not parent repo's .git
	const dotGitPath = path.join(deliverablesPath, ".git");
	try {
		await fs.stat(dotGitPath);
		return;
	} catch {
		// .git doesn't exist, proceed with init
	}

	await executeGitCommandWithRetry(
		["git", "init"],
		deliverablesPath,
		"init deliverables repo",
	);
	await executeGitCommandWithRetry(
		[
			"git",
			"commit",
			"--allow-empty",
			"-m",
			"📍 Initial deliverables checkpoint",
		],
		deliverablesPath,
		"initial checkpoint",
	);
}
