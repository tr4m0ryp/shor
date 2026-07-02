// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Audit system type definitions
 */

/**
 * Cross-cutting session metadata used by services, temporal, and audit.
 */
export interface SessionMetadata {
	id: string;
	webUrl: string;
	repoPath?: string;
	outputPath?: string;
	[key: string]: unknown;
}

/**
 * Result data passed to audit system when an agent execution ends.
 * Used by both AuditSession and MetricsTracker.
 */
export interface AgentEndResult {
	attemptNumber: number;
	duration_ms: number;
	success: boolean;
	model?: string | undefined;
	error?: string | undefined;
	checkpoint?: string | undefined;
	isFinalAttempt?: boolean | undefined;
	input_tokens?: number | undefined;
	output_tokens?: number | undefined;
	cache_read_input_tokens?: number | undefined;
	cache_creation_input_tokens?: number | undefined;
	num_turns?: number | undefined;
}
