// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
