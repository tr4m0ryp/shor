// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Error type definitions
 */

/**
 * Specific error codes for reliable classification.
 *
 * ErrorCode provides precision within the coarse 8-category PentestErrorType.
 * Used by classifyErrorForTemporal for code-based classification (preferred)
 * with string matching as fallback for external errors.
 */
export enum ErrorCode {
	// Config errors (PentestErrorType: 'config')
	CONFIG_NOT_FOUND = "CONFIG_NOT_FOUND",
	CONFIG_VALIDATION_FAILED = "CONFIG_VALIDATION_FAILED",
	CONFIG_PARSE_ERROR = "CONFIG_PARSE_ERROR",

	// Agent execution errors (PentestErrorType: 'validation')
	AGENT_EXECUTION_FAILED = "AGENT_EXECUTION_FAILED",
	OUTPUT_VALIDATION_FAILED = "OUTPUT_VALIDATION_FAILED",

	// Billing errors (PentestErrorType: 'billing')
	API_RATE_LIMITED = "API_RATE_LIMITED",
	SPENDING_CAP_REACHED = "SPENDING_CAP_REACHED",
	INSUFFICIENT_CREDITS = "INSUFFICIENT_CREDITS",

	// Git errors (PentestErrorType: 'filesystem')
	GIT_CHECKPOINT_FAILED = "GIT_CHECKPOINT_FAILED",
	GIT_ROLLBACK_FAILED = "GIT_ROLLBACK_FAILED",

	// Prompt errors (PentestErrorType: 'prompt')
	PROMPT_LOAD_FAILED = "PROMPT_LOAD_FAILED",

	// Validation errors (PentestErrorType: 'validation')
	DELIVERABLE_NOT_FOUND = "DELIVERABLE_NOT_FOUND",

	// Preflight validation errors
	REPO_NOT_FOUND = "REPO_NOT_FOUND",
	TARGET_UNREACHABLE = "TARGET_UNREACHABLE",
	AUTH_FAILED = "AUTH_FAILED",
	BILLING_ERROR = "BILLING_ERROR",
	TOOLING_MISSING = "TOOLING_MISSING",
}

export type PentestErrorType =
	| "config"
	| "network"
	| "tool"
	| "prompt"
	| "filesystem"
	| "validation"
	| "billing"
	| "unknown";

export interface PentestErrorContext {
	[key: string]: unknown;
}

export interface LogEntry {
	timestamp: string;
	context: string;
	error: {
		name: string;
		message: string;
		type: PentestErrorType;
		retryable: boolean;
		stack?: string;
	};
}

export interface ToolErrorResult {
	tool: string;
	output: string;
	status: "error";
	duration: number;
	success: false;
	error: Error;
}

export interface PromptErrorResult {
	success: false;
	error: Error;
}
