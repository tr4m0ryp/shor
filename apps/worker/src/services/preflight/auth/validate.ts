// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Credential preflight validation.
 *
 * Handles every supported auth path before the pipeline starts:
 * - Caller-supplied `providerConfig` (validated by the executor)
 * - Custom Anthropic-compatible base URL (single SDK round-trip)
 * - AWS Bedrock (required env vars)
 * - Google Vertex AI (required env vars + service account file)
 * - Default Anthropic API key / OAuth token (single SDK round-trip)
 */

import fs from "node:fs/promises";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { resolveModel } from "../../../ai/models.js";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { ErrorCode } from "../../../types/errors.js";
import { err, ok, type Result } from "../../../types/result.js";
import { isRetryableError, PentestError } from "../../error-handling.js";
import { classifySdkError } from "./classify-error.js";

/** Validate credentials via a minimal Claude Agent SDK query. */
export async function validateCredentials(
	logger: ActivityLogger,
	apiKey?: string,
	providerConfig?: import("../../../types/config.js").ProviderConfig,
): Promise<Result<void, PentestError>> {
	// 0. If providerConfig is present, credentials are managed by the caller.
	//    The executor will map providerConfig directly to sdkEnv — no process.env needed.
	if (providerConfig) {
		logger.info(
			`Provider config present (type: ${providerConfig.providerType || "anthropic_api"}) — skipping env-based credential validation`,
		);
		return ok(undefined);
	}

	// 0b. If apiKey provided via config, set it in env for SDK validation
	//     This avoids requiring process.env.ANTHROPIC_API_KEY when key is threaded via input
	if (apiKey) {
		process.env.ANTHROPIC_API_KEY = apiKey;
	}

	// 0c. DeepSeek auto-detection for validation
	if (process.env.DEEPSEEK_API_KEY && !process.env.ANTHROPIC_BASE_URL) {
		process.env.ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic";
		process.env.ANTHROPIC_AUTH_TOKEN = process.env.DEEPSEEK_API_KEY;
	}
	// 1. Custom base URL — validate endpoint is reachable via SDK query
	if (process.env.ANTHROPIC_BASE_URL && process.env.ANTHROPIC_AUTH_TOKEN) {
		const baseUrl = process.env.ANTHROPIC_BASE_URL;
		logger.info(`Validating custom base URL: ${baseUrl}`);

		try {
			for await (const message of query({
				prompt: "hi",
				options: { model: resolveModel("small"), maxTurns: 1 },
			})) {
				if (message.type === "assistant" && message.error) {
					return classifySdkError(
						message.error,
						`custom endpoint (${baseUrl})`,
					);
				}
				if (message.type === "result") {
					break;
				}
			}

			logger.info("Custom base URL OK");
			return ok(undefined);
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			return err(
				new PentestError(
					`Custom base URL unreachable: ${baseUrl} — ${message}`,
					"network",
					false,
					{ baseUrl },
					ErrorCode.AUTH_FAILED,
				),
			);
		}
	}

	// 2. Bedrock mode — validate required AWS credentials are present
	if (process.env.CLAUDE_CODE_USE_BEDROCK === "1") {
		const required = [
			"AWS_REGION",
			"AWS_BEARER_TOKEN_BEDROCK",
			"ANTHROPIC_SMALL_MODEL",
			"ANTHROPIC_MEDIUM_MODEL",
			"ANTHROPIC_LARGE_MODEL",
		];
		const missing = required.filter((v) => !process.env[v]);
		if (missing.length > 0) {
			return err(
				new PentestError(
					`Bedrock mode requires the following env vars in .env: ${missing.join(", ")}`,
					"config",
					false,
					{ missing },
					ErrorCode.AUTH_FAILED,
				),
			);
		}
		logger.info("Bedrock credentials OK");
		return ok(undefined);
	}

	// 3. Vertex AI mode — validate required GCP credentials are present
	if (process.env.CLAUDE_CODE_USE_VERTEX === "1") {
		const required = [
			"CLOUD_ML_REGION",
			"ANTHROPIC_VERTEX_PROJECT_ID",
			"ANTHROPIC_SMALL_MODEL",
			"ANTHROPIC_MEDIUM_MODEL",
			"ANTHROPIC_LARGE_MODEL",
		];
		const missing = required.filter((v) => !process.env[v]);
		if (missing.length > 0) {
			return err(
				new PentestError(
					`Vertex AI mode requires the following env vars in .env: ${missing.join(", ")}`,
					"config",
					false,
					{ missing },
					ErrorCode.AUTH_FAILED,
				),
			);
		}
		// Validate service account credentials file is accessible
		const credPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
		if (!credPath) {
			return err(
				new PentestError(
					"Vertex AI mode requires GOOGLE_APPLICATION_CREDENTIALS pointing to a service account key JSON file",
					"config",
					false,
					{},
					ErrorCode.AUTH_FAILED,
				),
			);
		}
		try {
			await fs.access(credPath);
		} catch {
			return err(
				new PentestError(
					`Service account key file not found at: ${credPath}`,
					"config",
					false,
					{ credPath },
					ErrorCode.AUTH_FAILED,
				),
			);
		}
		logger.info("Vertex AI credentials OK");
		return ok(undefined);
	}

	// 5. Check that at least one credential is present
	//    (DEEPSEEK_API_KEY was translated to ANTHROPIC_BASE_URL + ANTHROPIC_AUTH_TOKEN at step 0c)
	if (
		!process.env.ANTHROPIC_API_KEY &&
		!process.env.CLAUDE_CODE_OAUTH_TOKEN &&
		!process.env.ANTHROPIC_AUTH_TOKEN
	) {
		return err(
			new PentestError(
				"No API credentials found. Set DEEPSEEK_API_KEY or ANTHROPIC_API_KEY in .env",
				"config",
				false,
				{},
				ErrorCode.AUTH_FAILED,
			),
		);
	}

	// 6. Validate via SDK query
	const authType = process.env.CLAUDE_CODE_OAUTH_TOKEN
		? "OAuth token"
		: "API key";
	logger.info(`Validating ${authType} via SDK...`);

	try {
		for await (const message of query({
			prompt: "hi",
			options: { model: resolveModel("small"), maxTurns: 1 },
		})) {
			if (message.type === "assistant" && message.error) {
				return classifySdkError(message.error, authType);
			}
			if (message.type === "result") {
				break;
			}
		}

		logger.info(`${authType} OK`);
		return ok(undefined);
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		const retryable = isRetryableError(
			error instanceof Error ? error : new Error(message),
		);

		return err(
			new PentestError(
				retryable
					? `Failed to reach AI API. Check your network connection.`
					: `${authType} validation failed: ${message}`,
				retryable ? "network" : "config",
				retryable,
				{ authType },
				retryable ? undefined : ErrorCode.AUTH_FAILED,
			),
		);
	}
}
