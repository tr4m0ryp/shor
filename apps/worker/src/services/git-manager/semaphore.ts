// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Serializes git operations to prevent index.lock conflicts during parallel agent execution.
export class GitSemaphore {
	private queue: Array<() => void> = [];
	private running: boolean = false;

	async acquire(): Promise<void> {
		return new Promise((resolve) => {
			this.queue.push(resolve);
			this.process();
		});
	}

	release(): void {
		this.running = false;
		this.process();
	}

	private process(): void {
		if (!this.running && this.queue.length > 0) {
			this.running = true;
			const resolve = this.queue.shift();
			resolve?.();
		}
	}
}

export const gitSemaphore = new GitSemaphore();

const GIT_LOCK_ERROR_PATTERNS = [
	"index.lock",
	"unable to lock",
	"Another git process",
	"fatal: Unable to create",
	"fatal: index file",
];

export function isGitLockError(errorMessage: string): boolean {
	return GIT_LOCK_ERROR_PATTERNS.some((pattern) =>
		errorMessage.includes(pattern),
	);
}
