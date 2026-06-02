// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
