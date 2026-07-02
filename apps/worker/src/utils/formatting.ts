// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Formatting Utilities
 *
 * Generic formatting functions for durations, timestamps, and percentages.
 */

/**
 * Format duration in milliseconds to human-readable string
 */
export function formatDuration(ms: number): string {
	if (ms < 1000) {
		return `${ms}ms`;
	}

	const seconds = ms / 1000;
	if (seconds < 60) {
		return `${seconds.toFixed(1)}s`;
	}

	const minutes = Math.floor(seconds / 60);
	const remainingSeconds = Math.floor(seconds % 60);
	return `${minutes}m ${remainingSeconds}s`;
}

/**
 * Format timestamp to ISO 8601 string
 */
export function formatTimestamp(timestamp: number = Date.now()): string {
	return new Date(timestamp).toISOString();
}

/**
 * Calculate percentage
 */
export function calculatePercentage(part: number, total: number): number {
	if (total === 0) return 0;
	return (part / total) * 100;
}

/**
 * Extract agent type from description string for display purposes
 */
export function extractAgentType(description: string): string {
	if (description.includes("Pre-recon")) {
		return "pre-reconnaissance";
	}
	if (description.includes("Recon")) {
		return "reconnaissance";
	}
	if (description.includes("Report")) {
		return "report generation";
	}
	return "analysis";
}
