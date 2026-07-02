// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * String-pattern based retry classification.
 *
 * Used as a fallback when the error has no ErrorCode. Conservative by
 * default: unknown errors are NOT retried unless they match a retryable
 * pattern (fail-safe).
 */

const RETRYABLE_PATTERNS = [
	// Network and connection errors
	"network",
	"connection",
	"timeout",
	"econnreset",
	"enotfound",
	"econnrefused",
	// Rate limiting
	"rate limit",
	"429",
	"too many requests",
	// Server errors
	"server error",
	"5xx",
	"internal server error",
	"service unavailable",
	"bad gateway",
	// Claude API errors
	"model unavailable",
	"service temporarily unavailable",
	"api error",
	"terminated",
	// Max turns
	"max turns",
	"maximum turns",
];

// Patterns that indicate non-retryable errors (checked before default)
const NON_RETRYABLE_PATTERNS = [
	"authentication",
	"invalid prompt",
	"out of memory",
	"permission denied",
	"session limit reached",
	"invalid api key",
];

// Conservative retry classification - unknown errors don't retry (fail-safe default)
export function isRetryableError(error: Error): boolean {
	const message = error.message.toLowerCase();

	if (NON_RETRYABLE_PATTERNS.some((pattern) => message.includes(pattern))) {
		return false;
	}

	return RETRYABLE_PATTERNS.some((pattern) => message.includes(pattern));
}
