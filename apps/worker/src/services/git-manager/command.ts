// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { $ } from "zx";
import { ErrorCode } from "../../types/errors.js";
import { PentestError } from "../error-handling.js";
import { gitSemaphore, isGitLockError } from "./semaphore.js";

/** Retries git commands on lock conflicts with exponential backoff. */
export async function executeGitCommandWithRetry(
	commandArgs: string[],
	sourceDir: string,
	description: string,
	maxRetries: number = 5,
): Promise<{ stdout: string; stderr: string }> {
	await gitSemaphore.acquire();

	try {
		for (let attempt = 1; attempt <= maxRetries; attempt++) {
			try {
				const [cmd, ...args] = commandArgs;
				const result = await $`cd ${sourceDir} && ${cmd} ${args}`;
				return result;
			} catch (error) {
				const errMsg = error instanceof Error ? error.message : String(error);

				if (isGitLockError(errMsg) && attempt < maxRetries) {
					const delay = 2 ** (attempt - 1) * 1000;
					// executeGitCommandWithRetry is also called outside activity context
					// (e.g., from resume logic), so console.warn is the fallback here.
					console.warn(
						`Git lock conflict during ${description} (attempt ${attempt}/${maxRetries}). Retrying in ${delay}ms...`,
					);
					await new Promise((resolve) => setTimeout(resolve, delay));
					continue;
				}

				throw error;
			}
		}
		throw new PentestError(
			`Git command failed after ${maxRetries} retries`,
			"filesystem",
			true, // Retryable - transient git lock issues
			{ maxRetries, description },
			ErrorCode.GIT_CHECKPOINT_FAILED,
		);
	} finally {
		gitSemaphore.release();
	}
}
