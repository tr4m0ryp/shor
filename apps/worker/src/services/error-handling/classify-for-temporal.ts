// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Top-level Temporal error classifier.
 *
 * Activities call this to wrap errors in ApplicationFailure. Order matters:
 * code-based classification first (most reliable), then targeted string
 * matching for external SDK / network errors, ending with a TransientError
 * default that lets Temporal retry under its configured backoff.
 */

import {
	matchesBillingApiPattern,
	matchesBillingTextPattern,
} from "../../utils/billing-detection.js";
import { classifyByErrorCode } from "./classify-by-code.js";
import { PentestError } from "./pentest-error.js";

/**
 * Classifies errors for Temporal workflow retry behavior.
 * Returns error type and whether Temporal should retry.
 *
 * Used by activities to wrap errors in ApplicationFailure:
 * - Retryable errors: Temporal retries with configured backoff
 * - Non-retryable errors: Temporal fails immediately
 *
 * Classification priority:
 * 1. If error is PentestError with ErrorCode, classify by code (reliable)
 * 2. Fall through to string matching for external errors (SDK, network, etc.)
 */
export function classifyErrorForTemporal(error: unknown): {
	type: string;
	retryable: boolean;
} {
	// === CODE-BASED CLASSIFICATION (Preferred for internal errors) ===
	if (error instanceof PentestError && error.code !== undefined) {
		return classifyByErrorCode(error.code, error.retryable);
	}

	// === STRING-BASED CLASSIFICATION (Fallback for external errors) ===
	const message = (
		error instanceof Error ? error.message : String(error)
	).toLowerCase();

	// === BILLING ERRORS (Retryable with long backoff) ===
	// Anthropic returns billing as 400 invalid_request_error
	// Human can add credits OR wait for spending cap to reset (5-30 min backoff)
	// Check both API patterns and text patterns for comprehensive detection
	if (matchesBillingApiPattern(message) || matchesBillingTextPattern(message)) {
		return { type: "BillingError", retryable: true };
	}

	// === PERMANENT ERRORS (Non-retryable) ===

	// Authentication (401) - bad API key won't fix itself
	if (
		message.includes("authentication") ||
		message.includes("api key") ||
		message.includes("401") ||
		message.includes("authentication_error")
	) {
		return { type: "AuthenticationError", retryable: false };
	}

	// Permission (403) - access won't be granted
	if (
		message.includes("permission") ||
		message.includes("forbidden") ||
		message.includes("403")
	) {
		return { type: "PermissionError", retryable: false };
	}

	// === OUTPUT VALIDATION ERRORS (Retryable) ===
	// Agent didn't produce expected deliverables - retry may succeed
	// IMPORTANT: Must come BEFORE generic 'validation' check below
	if (
		message.includes("failed output validation") ||
		message.includes("output validation failed")
	) {
		return { type: "OutputValidationError", retryable: true };
	}

	// Invalid Request (400) - malformed request is permanent
	// Note: Checked AFTER billing and AFTER output validation
	if (
		message.includes("invalid_request_error") ||
		message.includes("malformed") ||
		message.includes("validation")
	) {
		return { type: "InvalidRequestError", retryable: false };
	}

	// Request Too Large (413) - won't fit no matter how many retries
	if (
		message.includes("request_too_large") ||
		message.includes("too large") ||
		message.includes("413")
	) {
		return { type: "RequestTooLargeError", retryable: false };
	}

	// Configuration errors - missing files need manual fix
	if (
		message.includes("enoent") ||
		message.includes("no such file") ||
		message.includes("cli not installed")
	) {
		return { type: "ConfigurationError", retryable: false };
	}

	// Execution limits - max turns/budget reached
	if (
		message.includes("max turns") ||
		message.includes("budget") ||
		message.includes("execution limit") ||
		message.includes("error_max_turns") ||
		message.includes("error_max_budget")
	) {
		return { type: "ExecutionLimitError", retryable: false };
	}

	// Invalid target URL - bad URL format won't fix itself
	if (
		message.includes("invalid url") ||
		message.includes("invalid target") ||
		message.includes("malformed url") ||
		message.includes("invalid uri")
	) {
		return { type: "InvalidTargetError", retryable: false };
	}

	// === TRANSIENT ERRORS (Retryable) ===
	// Rate limits (429), server errors (5xx), network issues
	// Let Temporal retry with configured backoff
	return { type: "TransientError", retryable: true };
}
