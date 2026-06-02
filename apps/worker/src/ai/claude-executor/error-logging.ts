// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";
import { deliverablesDir } from "../../paths.js";
import { isRetryableError } from "../../services/error-handling.js";
import { formatTimestamp } from "../../utils/formatting.js";

/** Emit a sequence of lines to stdout in order. */
export function outputLines(lines: string[]): void {
	for (const line of lines) {
		console.log(line);
	}
}

/** Append a structured JSON error record to the workspace's error.log. Best-effort: never throws. */
export async function writeErrorLog(
	err: Error & { code?: string; status?: number },
	sourceDir: string,
	fullPrompt: string,
	duration: number,
): Promise<void> {
	try {
		const errorLog = {
			timestamp: formatTimestamp(),
			agent: "claude-executor",
			error: {
				name: err.constructor.name,
				message: err.message,
				code: err.code,
				status: err.status,
				stack: err.stack,
			},
			context: {
				sourceDir,
				prompt: `${fullPrompt.slice(0, 200)}...`,
				retryable: isRetryableError(err),
			},
			duration,
		};
		const logPath = path.join(deliverablesDir(sourceDir), "error.log");
		await fs.appendFile(logPath, `${JSON.stringify(errorLog)}\n`);
	} catch {
		// Best-effort error log writing - don't propagate failures
	}
}
