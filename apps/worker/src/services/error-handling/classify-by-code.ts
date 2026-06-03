// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Code-based classification of PentestError into Temporal-friendly
 * { type, retryable } pairs. Preferred path for internal errors because
 * it is deterministic and does not depend on message string matching.
 */

import { ErrorCode } from "../../types/errors.js";

/**
 * Classifies errors by ErrorCode for reliable, code-based classification.
 * Used when error is a PentestError with a specific ErrorCode.
 */
export function classifyByErrorCode(
	code: ErrorCode,
	retryableFromError: boolean,
): { type: string; retryable: boolean } {
	switch (code) {
		// Billing errors - retryable (wait for cap reset or credits added)
		case ErrorCode.SPENDING_CAP_REACHED:
		case ErrorCode.INSUFFICIENT_CREDITS:
			return { type: "BillingError", retryable: true };

		case ErrorCode.API_RATE_LIMITED:
			return { type: "RateLimitError", retryable: true };

		// Config errors - non-retryable (need manual fix)
		case ErrorCode.CONFIG_NOT_FOUND:
		case ErrorCode.CONFIG_VALIDATION_FAILED:
		case ErrorCode.CONFIG_PARSE_ERROR:
			return { type: "ConfigurationError", retryable: false };

		// Prompt errors - non-retryable (need manual fix)
		case ErrorCode.PROMPT_LOAD_FAILED:
			return { type: "ConfigurationError", retryable: false };

		// Git errors - non-retryable (indicates workspace corruption)
		case ErrorCode.GIT_CHECKPOINT_FAILED:
		case ErrorCode.GIT_ROLLBACK_FAILED:
			return { type: "GitError", retryable: false };

		// Validation errors - retryable (agent may succeed on retry)
		case ErrorCode.OUTPUT_VALIDATION_FAILED:
		case ErrorCode.DELIVERABLE_NOT_FOUND:
			return { type: "OutputValidationError", retryable: true };

		// Agent execution - use the retryable flag from the error
		case ErrorCode.AGENT_EXECUTION_FAILED:
			return { type: "AgentExecutionError", retryable: retryableFromError };

		// Preflight validation errors
		case ErrorCode.REPO_NOT_FOUND:
			return { type: "ConfigurationError", retryable: false };

		// Missing skills / tool binaries — needs an image rebuild, never self-heals.
		case ErrorCode.TOOLING_MISSING:
			return { type: "ConfigurationError", retryable: false };

		case ErrorCode.AUTH_FAILED:
			return { type: "AuthenticationError", retryable: false };

		case ErrorCode.BILLING_ERROR:
			return { type: "BillingError", retryable: true };

		default:
			// Unknown code - fall through to string matching
			return { type: "UnknownError", retryable: retryableFromError };
	}
}
