// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { formatDuration } from "../../utils/formatting.js";
import type { ExecutionContext, ResultData } from "../types.js";
import { getAgentPrefix } from "./agent-prefix.js";

export function formatAssistantOutput(
	cleanedContent: string,
	context: ExecutionContext,
	turnCount: number,
	description: string,
): string[] {
	if (!cleanedContent.trim()) {
		return [];
	}

	const lines: string[] = [];

	if (context.isParallelExecution) {
		// Compact output for parallel agents with prefixes
		const prefix = getAgentPrefix(description);
		lines.push(`${prefix} ${cleanedContent}`);
	} else {
		// Full turn output for sequential agents
		lines.push(`\n    Turn ${turnCount} (${description}):`);
		lines.push(`    ${cleanedContent}`);
	}

	return lines;
}

export function formatResultOutput(
	data: ResultData,
	showFullResult: boolean,
): string[] {
	const lines: string[] = [];

	lines.push(`\n    COMPLETED:`);
	lines.push(`    Duration: ${(data.duration_ms / 1000).toFixed(1)}s`);

	if (data.subtype === "error_max_turns") {
		lines.push(`    Stopped: Hit maximum turns limit`);
	} else if (data.subtype === "error_during_execution") {
		lines.push(`    Stopped: Execution error`);
	}

	if (data.permissionDenials > 0) {
		lines.push(`    ${data.permissionDenials} permission denials`);
	}

	if (showFullResult && data.result && typeof data.result === "string") {
		if (data.result.length > 1000) {
			lines.push(
				`    ${data.result.slice(0, 1000)}... [${data.result.length} total chars]`,
			);
		} else {
			lines.push(`    ${data.result}`);
		}
	}

	return lines;
}

export function formatErrorOutput(
	_error: Error & { code?: string; status?: number },
	context: ExecutionContext,
	description: string,
	duration: number,
	_sourceDir: string,
	_isRetryable: boolean,
): string[] {
	const lines: string[] = [];

	if (context.isParallelExecution) {
		const prefix = getAgentPrefix(description);
		lines.push(`${prefix} Failed (${formatDuration(duration)})`);
	} else if (context.useCleanOutput) {
		lines.push(`${context.agentType} failed (${formatDuration(duration)})`);
	} else {
		lines.push(`  Agent failed: ${description} (${formatDuration(duration)})`);
	}

	return lines;
}

export function formatCompletionMessage(
	_execContext: ExecutionContext,
	description: string,
	turnCount: number,
	duration: number,
): string {
	return `  Agent completed: ${description} (${turnCount} turns) in ${formatDuration(duration)}`;
}

export function formatToolUseOutput(
	toolName: string,
	input: Record<string, unknown> | undefined,
): string[] {
	const lines: string[] = [];

	lines.push(`\n    Using Tool: ${toolName}`);
	if (input && Object.keys(input).length > 0) {
		lines.push(`    Input: ${JSON.stringify(input, null, 2)}`);
	}

	return lines;
}

export function formatToolResultOutput(displayContent: string): string[] {
	const lines: string[] = [];

	lines.push(`    Tool Result:`);
	if (displayContent) {
		lines.push(`    ${displayContent}`);
	}

	return lines;
}
