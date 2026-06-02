// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { C_BOLD, C_BRAND, C_FG, C_MUTED, C_RESET } from "./colors.js";
import { formatDuration, getStatusDisplay, truncate } from "./format.js";
import type { WorkspaceInfo } from "./types.js";

const NAME_WIDTH = 30;
const URL_WIDTH = 30;
const STATUS_WIDTH = 14;
const DURATION_WIDTH = 10;
const TOTAL_WIDTH = NAME_WIDTH + URL_WIDTH + STATUS_WIDTH + DURATION_WIDTH;

/** Print the table header (title banner + column labels). */
export function renderHeader(): void {
	console.log(`\n  ${C_BRAND}${"─".repeat(TOTAL_WIDTH)}${C_RESET}`);
	console.log(`  ${C_BOLD}${C_BRAND}Storron Workspaces${C_RESET}`);
	console.log(`  ${C_BRAND}${"─".repeat(TOTAL_WIDTH)}${C_RESET}`);

	console.log(
		`  ${C_BRAND}WORKSPACE${C_RESET}`.padEnd(NAME_WIDTH + 9) +
			`${C_BRAND}URL${C_RESET}`.padEnd(URL_WIDTH + 4) +
			`${C_BRAND}STATUS${C_RESET}`.padEnd(STATUS_WIDTH + 4) +
			`${C_BRAND}DURATION${C_RESET}`,
	);
	console.log(`  ${C_MUTED}${"─".repeat(TOTAL_WIDTH)}${C_RESET}`);
}

/** Print a single workspace row. Returns true if this workspace is resumable. */
export function renderRow(ws: WorkspaceInfo): boolean {
	const now = new Date();
	const endTime = ws.completedAt || now;
	const durationMs = endTime.getTime() - ws.createdAt.getTime();
	const duration = formatDuration(durationMs);
	const isResumable = ws.status !== "completed";

	const resumeTag = isResumable ? ` ${C_BRAND}(resumable)${C_RESET}` : "";
	const statusDisplay = getStatusDisplay(ws.status);

	console.log(
		`  ${C_FG}${truncate(ws.name, NAME_WIDTH - 2).padEnd(NAME_WIDTH)}${C_RESET}` +
			`${C_MUTED}${truncate(ws.url, URL_WIDTH - 2).padEnd(URL_WIDTH)}${C_RESET}` +
			statusDisplay.padEnd(STATUS_WIDTH + 9) +
			`${C_FG}${duration.padEnd(DURATION_WIDTH)}${C_RESET}` +
			resumeTag,
	);

	return isResumable;
}

/** Print the trailing summary line and (when applicable) the resume hint. */
export function renderFooter(
	workspaceCount: number,
	resumableCount: number,
): void {
	console.log(`  ${C_MUTED}${"─".repeat(TOTAL_WIDTH)}${C_RESET}`);
	console.log();
	const summary = `${C_FG}${workspaceCount} workspace${workspaceCount === 1 ? "" : "s"} found${C_RESET}`;
	const resumeSummary =
		resumableCount > 0
			? ` ${C_BRAND}(${resumableCount} resumable)${C_RESET}`
			: "";
	console.log(`  ${summary}${resumeSummary}`);

	if (resumableCount > 0) {
		console.log(
			`\n  ${C_BRAND}Resume with:${C_RESET} ${C_FG}./storron start -u <url> -r <repo> -w <name>${C_RESET}`,
		);
	}

	console.log();
}
