// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Maps Claude Agent SDK assistant-message error codes to preflight-level
 * `PentestError` instances with user-actionable messages. Used by the
 * credential validator after a single round-trip query.
 */

import type { SDKAssistantMessageError } from "@anthropic-ai/claude-agent-sdk";
import { ErrorCode } from "../../../types/errors.js";
import { err, type Result } from "../../../types/result.js";
import { PentestError } from "../../error-handling.js";

/** Map SDK error type to a human-readable preflight PentestError. */
export function classifySdkError(
	sdkError: SDKAssistantMessageError,
	authType: string,
): Result<void, PentestError> {
	switch (sdkError) {
		case "authentication_failed":
			return err(
				new PentestError(
					`Invalid ${authType}. Check your credentials in .env and try again.`,
					"config",
					false,
					{ authType, sdkError },
					ErrorCode.AUTH_FAILED,
				),
			);
		case "billing_error":
			return err(
				new PentestError(
					`Anthropic account has a billing issue. Add credits or check your billing dashboard.`,
					"billing",
					true,
					{ authType, sdkError },
					ErrorCode.BILLING_ERROR,
				),
			);
		case "rate_limit":
			return err(
				new PentestError(
					`Anthropic rate limit or spending cap reached. Wait a few minutes and try again.`,
					"billing",
					true,
					{ authType, sdkError },
					ErrorCode.BILLING_ERROR,
				),
			);
		case "server_error":
			return err(
				new PentestError(
					`Anthropic API is temporarily unavailable. Try again shortly.`,
					"network",
					true,
					{
						authType,
						sdkError,
					},
				),
			);
		default:
			return err(
				new PentestError(
					`${authType} validation failed unexpectedly. Check your credentials in .env.`,
					"config",
					false,
					{ authType, sdkError },
					ErrorCode.AUTH_FAILED,
				),
			);
	}
}
