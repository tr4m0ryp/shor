// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/** Format timestamp for log line (local time, human readable). */
export function formatLogTime(): string {
	const now = new Date();
	return now.toISOString().replace("T", " ").slice(0, 19);
}

/** Truncate string to max length with ellipsis. */
export function truncate(str: string, maxLen: number): string {
	if (str.length <= maxLen) return str;
	return `${str.slice(0, maxLen - 3)}...`;
}

/** Format tool parameters for human-readable display. */
export function formatToolParams(toolName: string, params: unknown): string {
	if (!params || typeof params !== "object") {
		return "";
	}

	const p = params as Record<string, unknown>;

	// Tool-specific formatting for common tools
	switch (toolName) {
		case "Bash":
			if (p.command) {
				return truncate(String(p.command).replace(/\n/g, " "), 100);
			}
			break;
		case "Read":
			if (p.file_path) {
				return String(p.file_path);
			}
			break;
		case "Write":
			if (p.file_path) {
				return String(p.file_path);
			}
			break;
		case "Edit":
			if (p.file_path) {
				return String(p.file_path);
			}
			break;
		case "Glob":
			if (p.pattern) {
				return String(p.pattern);
			}
			break;
		case "Grep":
			if (p.pattern) {
				const path = p.path ? ` in ${p.path}` : "";
				return `"${truncate(String(p.pattern), 50)}"${path}`;
			}
			break;
		case "WebFetch":
			if (p.url) {
				return String(p.url);
			}
			break;
	}

	// Default: show first string-valued param truncated
	for (const [key, val] of Object.entries(p)) {
		if (typeof val === "string" && val.length > 0) {
			return `${key}=${truncate(val, 60)}`;
		}
	}

	return "";
}

/**
 * Format a pipe-delimited error string into indented multi-line display.
 *
 * Input:  "phase context|ErrorType|message|Hint: ..."
 * Output: "Error:       phase context\n             ErrorType\n             ..."
 */
export function formatErrorBlock(errorString: string): string {
	const segments = errorString.split("|");
	const label = "Error:       ";
	const indent = " ".repeat(label.length);

	const lines = segments.map((segment, i) =>
		i === 0 ? `${label}${segment.trim()}` : `${indent}${segment.trim()}`,
	);

	return `${lines.join("\n")}\n`;
}
