// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Preflight validation activity.
 *
 * Runs cheap checks before any agent execution. Not routed through
 * `runAgentActivity` because no SDK-backed agent runs here.
 */

import { ApplicationFailure, Context, heartbeat } from "@temporalio/activity";
import { classifyErrorForTemporal } from "../../services/error-handling.js";
import { runPreflightChecks } from "../../services/preflight.js";
import { isErr } from "../../types/result.js";
import { createActivityLogger } from "../activity-logger.js";
import {
	HEARTBEAT_INTERVAL_MS,
	truncateErrorMessage,
	truncateStackTrace,
} from "./_internal.js";
import type { ActivityInput } from "./types.js";

/**
 * Preflight validation activity.
 *
 * Runs cheap checks before any agent execution:
 * 1. Repository path exists with .git
 * 2. Config file validates (if provided)
 * 3. Credential validation (API key, OAuth, or router mode)
 * 4. Target URL reachable from the container
 *
 * NOT using runAgentActivity — preflight doesn't run an agent via the SDK.
 */
export async function runPreflightValidation(
	input: ActivityInput,
): Promise<void> {
	const startTime = Date.now();
	const attemptNumber = Context.current().info.attempt;

	const heartbeatInterval = setInterval(() => {
		const elapsed = Math.floor((Date.now() - startTime) / 1000);
		heartbeat({
			phase: "preflight",
			elapsedSeconds: elapsed,
			attempt: attemptNumber,
		});
	}, HEARTBEAT_INTERVAL_MS);

	try {
		const logger = createActivityLogger();
		logger.info("Running preflight validation...", { attempt: attemptNumber });

		const result = await runPreflightChecks(
			input.webUrl,
			input.repoPath,
			input.configPath,
			logger,
			input.skipGitCheck,
			input.apiKey,
			input.providerConfig,
		);

		if (isErr(result)) {
			const classified = classifyErrorForTemporal(result.error);
			const message = truncateErrorMessage(result.error.message);

			if (classified.retryable) {
				const failure = ApplicationFailure.create({
					message,
					type: classified.type,
					details: [
						{
							phase: "preflight",
							attemptNumber,
							elapsed: Date.now() - startTime,
						},
					],
				});
				truncateStackTrace(failure);
				throw failure;
			} else {
				const failure = ApplicationFailure.nonRetryable(
					message,
					classified.type,
					[
						{
							phase: "preflight",
							attemptNumber,
							elapsed: Date.now() - startTime,
						},
					],
				);
				truncateStackTrace(failure);
				throw failure;
			}
		}

		logger.info("Preflight validation passed");
	} catch (error) {
		if (error instanceof ApplicationFailure) {
			throw error;
		}

		const classified = classifyErrorForTemporal(error);
		const rawMessage = error instanceof Error ? error.message : String(error);
		const message = truncateErrorMessage(rawMessage);

		const failure = ApplicationFailure.nonRetryable(message, classified.type, [
			{ phase: "preflight", attemptNumber, elapsed: Date.now() - startTime },
		]);
		truncateStackTrace(failure);
		throw failure;
	} finally {
		clearInterval(heartbeatInterval);
	}
}
