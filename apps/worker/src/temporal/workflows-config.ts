// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Activity option constants for the workflow.
 *
 * Lives in its own module so the workflow file can stay focused on
 * orchestration.
 */

import type { ActivityOptions } from "@temporalio/workflow";

const SECOND_MS = 1_000;
const MINUTE_MS = 60 * SECOND_MS;
const HOUR_MS = 60 * MINUTE_MS;

/**
 * Non-retryable error classifications shared across all activity proxies.
 *
 * These map to errors raised by `services/error-handling.ts` and represent
 * conditions that cannot recover via retry: bad credentials, malformed
 * input, permission errors, etc.
 */
export const NON_RETRYABLE_ERROR_TYPES = [
	"AuthenticationError",
	"PermissionError",
	"InvalidRequestError",
	"RequestTooLargeError",
	"ConfigurationError",
	"InvalidTargetError",
	"ExecutionLimitError",
] as const;

// Retry configuration for production (long intervals for billing recovery)
const PRODUCTION_RETRY = {
	initialInterval: "5 minutes",
	maximumInterval: "30 minutes",
	backoffCoefficient: 2,
	maximumAttempts: 50,
	nonRetryableErrorTypes: [...NON_RETRYABLE_ERROR_TYPES],
};

// Retry configuration for subscription plans (5h+ rolling rate limit windows)
const SUBSCRIPTION_RETRY = {
	initialInterval: "5 minutes",
	maximumInterval: "6 hours",
	backoffCoefficient: 2,
	maximumAttempts: 100,
	nonRetryableErrorTypes: [...NON_RETRYABLE_ERROR_TYPES],
};

// Retry configuration for preflight validation (short timeout, few retries)
const PREFLIGHT_RETRY = {
	initialInterval: "10 seconds",
	maximumInterval: "1 minute",
	backoffCoefficient: 2,
	maximumAttempts: 3,
	nonRetryableErrorTypes: [...NON_RETRYABLE_ERROR_TYPES],
};

/**
 * Base activity options for the default (production) proxy.
 *
 * Durations are stored in milliseconds so the scaler can multiply directly.
 * The heartbeatTimeout is extended for sub-agent execution because the SDK
 * blocks the event loop during Task tool calls.
 */
export const BASE_ACTS_OPTIONS: ActivityOptions = {
	startToCloseTimeout: 2 * HOUR_MS,
	heartbeatTimeout: 60 * MINUTE_MS,
	retry: PRODUCTION_RETRY,
};

/**
 * Base activity options for subscription-plan recovery.
 *
 * Already extended to ride out multi-hour rate-limit windows.
 */
export const BASE_SUBSCRIPTION_ACTS_OPTIONS: ActivityOptions = {
	startToCloseTimeout: 8 * HOUR_MS,
	heartbeatTimeout: 2 * HOUR_MS,
	retry: SUBSCRIPTION_RETRY,
};

/**
 * Base activity options for preflight validation.
 *
 * Preflight runs a handful of HTTP requests, so the timeouts are short.
 */
export const BASE_PREFLIGHT_OPTIONS: ActivityOptions = {
	startToCloseTimeout: 2 * MINUTE_MS,
	heartbeatTimeout: 2 * MINUTE_MS,
	retry: PREFLIGHT_RETRY,
};
