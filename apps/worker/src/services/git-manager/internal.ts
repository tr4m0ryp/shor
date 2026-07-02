// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { ActivityLogger } from "../../types/activity-logger.js";

export interface GitOperationResult {
	success: boolean;
	hadChanges?: boolean;
	error?: Error;
}

/** Log a summary of changed files with truncation for long lists */
export function logChangeSummary(
	changes: string[],
	messageWithChanges: string,
	messageWithoutChanges: string,
	logger: ActivityLogger,
	level: "info" | "warn" = "info",
	maxToShow: number = 5,
): void {
	if (changes.length > 0) {
		const msg = messageWithChanges.replace("{count}", String(changes.length));
		const fileList = changes
			.slice(0, maxToShow)
			.map((c) => `  ${c}`)
			.join(", ");
		const suffix =
			changes.length > maxToShow
				? ` ... and ${changes.length - maxToShow} more files`
				: "";
		logger[level](`${msg} ${fileList}${suffix}`);
	} else {
		logger[level](messageWithoutChanges);
	}
}

/** Convert unknown error to GitOperationResult */
export function toErrorResult(error: unknown): GitOperationResult {
	const errMsg = error instanceof Error ? error.message : String(error);
	return {
		success: false,
		error: error instanceof Error ? error : new Error(errMsg),
	};
}
