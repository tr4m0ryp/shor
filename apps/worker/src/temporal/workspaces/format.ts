// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { C_BRAND, C_DESTRUCTIVE, C_RESET, C_SUCCESS } from "./colors.js";

/** Render an elapsed-milliseconds value as a short human string (e.g. `5s`, `12m`, `1h 30m`). */
export function formatDuration(ms: number): string {
	const seconds = Math.floor(ms / 1000);
	const minutes = Math.floor(seconds / 60);
	const hours = Math.floor(minutes / 60);

	if (hours > 0) {
		return `${hours}h ${minutes % 60}m`;
	}
	if (minutes > 0) {
		return `${minutes}m`;
	}
	return `${seconds}s`;
}

/** Wrap a workspace status string in the appropriate ANSI color codes. */
export function getStatusDisplay(status: string): string {
	switch (status) {
		case "completed":
			return `${C_SUCCESS}completed${C_RESET}`;
		case "failed":
			return `${C_DESTRUCTIVE}failed${C_RESET}`;
		default:
			return `${C_BRAND}${status}${C_RESET}`;
	}
}

/** Truncate `str` to `maxLen` characters, replacing the tail with a single-character ellipsis. */
export function truncate(str: string, maxLen: number): string {
	if (str.length <= maxLen) return str;
	return `${str.slice(0, maxLen - 1)}…`;
}
