// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { JsonSchemaOutputFormat } from "@anthropic-ai/claude-agent-sdk";
import type { AuditSession } from "../../audit/index.js";
import {
	isRetryableError,
	PentestError,
} from "../../services/error-handling.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { isSpendingCapBehavior } from "../../utils/billing-detection.js";
import { Timer } from "../../utils/metrics.js";
import { createAuditLogger } from "../audit-logger.js";
import { type ModelTier, resolveModel } from "../models.js";
import {
	detectExecutionContext,
	formatCompletionMessage,
	formatErrorOutput,
} from "../output-formatters.js";
import { createProgressManager } from "../progress-manager.js";
import { outputLines, writeErrorLog } from "./error-logging.js";
import { buildSdkEnv } from "./sdk-env.js";
import { processMessageStream } from "./stream-processor.js";
import type { ClaudePromptResult } from "./types.js";

/**
 * Low-level SDK execution. Handles message streaming, progress, and audit logging.
 * Exported for Temporal activities to call single-attempt execution.
 */
export async function runClaudePrompt(
	prompt: string,
	sourceDir: string,
	context: string = "",
	description: string = "Claude analysis",
	agentName: string | null = null,
	auditSession: AuditSession | null = null,
	logger: ActivityLogger,
	modelTier: ModelTier = "medium",
	outputFormat?: JsonSchemaOutputFormat,
	apiKey?: string,
	deliverablesSubdir?: string,
	providerConfig?: import("../../types/config.js").ProviderConfig,
	extraEnv?: Record<string, string>,
	maxTurns: number = 10_000,
): Promise<ClaudePromptResult> {
	// 1. Initialize timing and prompt
	const timer = new Timer(
		`agent-${description.toLowerCase().replace(/\s+/g, "-")}`,
	);
	const fullPrompt = context ? `${context}\n\n${prompt}` : prompt;

	// 2. Set up progress and audit infrastructure
	const execContext = detectExecutionContext(description);
	const progress = createProgressManager(
		{ description, useCleanOutput: execContext.useCleanOutput },
		global.STORRON_DISABLE_LOADER ?? false,
	);
	const auditLogger = createAuditLogger(auditSession);

	logger.info(`Running agent: ${description}...`);

	// 3. Build env vars to pass to SDK subprocesses
	const sdkEnv = await buildSdkEnv({
		sourceDir,
		agentName,
		apiKey,
		deliverablesSubdir,
		providerConfig,
		extraEnv,
		logger,
	});

	// 4. Configure SDK options
	// Model override from providerConfig takes precedence over env-based resolveModel
	const model =
		providerConfig?.modelOverrides?.[modelTier] ?? resolveModel(modelTier);
	// Point the SDK at the Claude Code JS CLI when provided (the runtime image
	// sets SHOR_CLAUDE_CLI). A `.js` path makes the SDK spawn `node <cli.js>`
	// instead of its bundled native binary, which fails to exec on glibc-dynamic.
	const claudeCli = process.env.SHOR_CLAUDE_CLI;
	const options = {
		model,
		maxTurns,
		cwd: sourceDir,
		permissionMode: "bypassPermissions" as const,
		allowDangerouslySkipPermissions: true,
		settingSources: ["user"] as ("user" | "project" | "local")[],
		env: sdkEnv,
		...(claudeCli && { pathToClaudeCodeExecutable: claudeCli }),
		...(outputFormat && { outputFormat }),
	};

	if (!execContext.useCleanOutput) {
		logger.info(
			`SDK Options: maxTurns=${options.maxTurns}, cwd=${sourceDir}, permissions=BYPASS`,
		);
	}

	let turnCount = 0;
	let result: string | null = null;
	let apiErrorDetected = false;

	progress.start();

	try {
		// 6. Process the message stream
		const messageLoopResult = await processMessageStream(
			fullPrompt,
			options,
			{ execContext, description, progress, auditLogger, logger, agentName },
			timer,
		);

		turnCount = messageLoopResult.turnCount;
		result = messageLoopResult.result;
		apiErrorDetected = messageLoopResult.apiErrorDetected;
		const model = messageLoopResult.model;

		// === SPENDING CAP SAFEGUARD ===
		// 7. Defense-in-depth: Detect spending cap that slipped through detectApiError().
		// Uses consolidated billing detection from utils/billing-detection.ts
		if (isSpendingCapBehavior(turnCount, result || "")) {
			throw new PentestError(
				`Spending cap likely reached (turns=${turnCount}): ${result?.slice(0, 100)}`,
				"billing",
				true, // Retryable - Temporal will use 5-30 min backoff
			);
		}

		// 8. Finalize successful result
		const duration = timer.stop();

		if (apiErrorDetected) {
			logger.warn(
				`API Error detected in ${description} - will validate deliverables before failing`,
			);
		}

		progress.finish(
			formatCompletionMessage(execContext, description, turnCount, duration),
		);

		return {
			result,
			success: true,
			duration,
			turns: messageLoopResult.numTurns ?? turnCount,
			model,
			apiErrorDetected,
			...(messageLoopResult.inputTokens !== undefined && {
				inputTokens: messageLoopResult.inputTokens,
			}),
			...(messageLoopResult.outputTokens !== undefined && {
				outputTokens: messageLoopResult.outputTokens,
			}),
			...(messageLoopResult.cacheReadInputTokens !== undefined && {
				cacheReadInputTokens: messageLoopResult.cacheReadInputTokens,
			}),
			...(messageLoopResult.cacheCreationInputTokens !== undefined && {
				cacheCreationInputTokens: messageLoopResult.cacheCreationInputTokens,
			}),
			...(messageLoopResult.structuredOutput !== undefined && {
				structuredOutput: messageLoopResult.structuredOutput,
			}),
		};
	} catch (error) {
		// 9. Handle errors — log, write error file, return failure
		const duration = timer.stop();

		const err = error as Error & { code?: string; status?: number };

		await auditLogger.logError(err, duration, turnCount);
		progress.stop();
		outputLines(
			formatErrorOutput(
				err,
				execContext,
				description,
				duration,
				sourceDir,
				isRetryableError(err),
			),
		);
		await writeErrorLog(err, sourceDir, fullPrompt, duration);

		return {
			error: err.message,
			errorType: err.constructor.name,
			prompt: `${fullPrompt.slice(0, 100)}...`,
			success: false,
			duration,
			retryable: isRetryableError(err),
		};
	}
}
