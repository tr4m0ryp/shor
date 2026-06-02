// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
