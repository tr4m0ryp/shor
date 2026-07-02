// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { SDKAssistantMessageError } from "@anthropic-ai/claude-agent-sdk";
import { PentestError } from "../../services/error-handling.js";
import { ErrorCode } from "../../types/errors.js";
import { matchesBillingTextPattern } from "../../utils/billing-detection.js";
import type { ApiErrorDetection } from "../types.js";

export function detectApiError(content: string): ApiErrorDetection {
	if (!content || typeof content !== "string") {
		return { detected: false };
	}

	const lowerContent = content.toLowerCase();

	// === BILLING/SPENDING CAP ERRORS (Retryable with long backoff) ===
	// When the API hits a spending cap, it returns a short message like
	// "Spending cap reached resets 8am" instead of throwing an error.
	// These should retry with 5-30 min backoff so workflows can recover when cap resets.
	if (matchesBillingTextPattern(content)) {
		return {
			detected: true,
			shouldThrow: new PentestError(
				`Billing limit reached: ${content.slice(0, 100)}`,
				"billing",
				true, // RETRYABLE - Temporal will use 5-30 min backoff
				{},
				ErrorCode.SPENDING_CAP_REACHED,
			),
		};
	}

	// === SESSION LIMIT (Non-retryable) ===
	// Different from spending cap - usually means something is fundamentally wrong
	if (lowerContent.includes("session limit reached")) {
		return {
			detected: true,
			shouldThrow: new PentestError("Session limit reached", "billing", false),
		};
	}

	// Non-fatal API errors - detected but continue
	if (
		lowerContent.includes("api error") ||
		lowerContent.includes("terminated")
	) {
		return { detected: true };
	}

	return { detected: false };
}

// Maps SDK structured error types to our error handling.
export function handleStructuredError(
	errorType: SDKAssistantMessageError,
	content: string,
): ApiErrorDetection {
	switch (errorType) {
		case "billing_error":
			return {
				detected: true,
				shouldThrow: new PentestError(
					`Billing error (structured): ${content.slice(0, 100)}`,
					"billing",
					true, // Retryable with backoff
					{},
					ErrorCode.INSUFFICIENT_CREDITS,
				),
			};
		case "rate_limit":
			return {
				detected: true,
				shouldThrow: new PentestError(
					`Rate limit hit (structured): ${content.slice(0, 100)}`,
					"network",
					true, // Retryable with backoff
					{},
					ErrorCode.API_RATE_LIMITED,
				),
			};
		case "authentication_failed":
			return {
				detected: true,
				shouldThrow: new PentestError(
					`Authentication failed: ${content.slice(0, 100)}`,
					"config",
					false, // Not retryable - needs API key fix
				),
			};
		case "server_error":
			return {
				detected: true,
				shouldThrow: new PentestError(
					`Server error (structured): ${content.slice(0, 100)}`,
					"network",
					true, // Retryable
				),
			};
		case "invalid_request":
			return {
				detected: true,
				shouldThrow: new PentestError(
					`Invalid request: ${content.slice(0, 100)}`,
					"config",
					false, // Not retryable - needs code fix
				),
			};
		case "max_output_tokens":
			return {
				detected: true,
				shouldThrow: new PentestError(
					`Max output tokens reached: ${content.slice(0, 100)}`,
					"billing",
					true, // Retryable - may succeed with different content
				),
			};
		default:
			return { detected: true };
	}
}
