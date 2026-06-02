// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { $ } from "zx";
import { executeGitCommandWithRetry } from "./command.js";

/**
 * Check if a directory is a git repository.
 * Returns true if the directory contains a .git folder or is inside a git repo.
 */
export async function isGitRepository(dir: string): Promise<boolean> {
	try {
		await $`cd ${dir} && git rev-parse --git-dir`.quiet();
		return true;
	} catch {
		return false;
	}
}

/** Get list of changed files from git status --porcelain output. */
export async function getChangedFiles(
	sourceDir: string,
	operationDescription: string,
): Promise<string[]> {
	const status = await executeGitCommandWithRetry(
		["git", "status", "--porcelain"],
		sourceDir,
		operationDescription,
	);
	return status.stdout
		.trim()
		.split("\n")
		.filter((line) => line.length > 0);
}

/**
 * Get current git commit hash.
 * Returns null if not a git repository.
 */
export async function getGitCommitHash(
	sourceDir: string,
): Promise<string | null> {
	if (!(await isGitRepository(sourceDir))) {
		return null;
	}
	try {
		const result = await $`cd ${sourceDir} && git rev-parse HEAD`;
		return result.stdout.trim();
	} catch {
		return null;
	}
}
