// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Core agent dispatch implementation.
 *
 * Wraps service calls with Temporal-specific concerns: heartbeat loop,
 * container lifecycle, and error classification into ApplicationFailure.
 */

import path from "node:path";
import { ApplicationFailure, Context, heartbeat } from "@temporalio/activity";
import { AuditSession } from "../../../audit/index.js";
import { deliverablesDir } from "../../../paths.js";
import { getOrCreateContainer } from "../../../services/container.js";
import {
	classifyErrorForTemporal,
	PentestError,
} from "../../../services/error-handling.js";
import type { AgentName } from "../../../types/agents.js";
import { ErrorCode } from "../../../types/errors.js";
import { createActivityLogger } from "../../activity-logger.js";
import type { AgentMetrics } from "../../shared.js";
import {
	buildContainerConfig,
	buildSessionMetadata,
	HEARTBEAT_INTERVAL_MS,
	MAX_OUTPUT_VALIDATION_RETRIES,
	truncateErrorMessage,
	truncateStackTrace,
} from "../_internal.js";
import type { ActivityInput } from "../types.js";

/**
 * Core activity implementation using services.
 *
 * Executes a single agent with:
 * 1. Heartbeat loop for worker liveness
 * 2. Container creation/reuse
 * 3. Service-based agent execution
 * 4. Error classification for Temporal retry
 */
export async function runAgentActivity(
	agentName: AgentName,
	input: ActivityInput,
): Promise<AgentMetrics> {
	const { repoPath, configPath, workflowId, webUrl } = input;
	const startTime = Date.now();
	const attemptNumber = Context.current().info.attempt;

	// Heartbeat loop - signals worker is alive to Temporal server
	const heartbeatInterval = setInterval(() => {
		const elapsed = Math.floor((Date.now() - startTime) / 1000);
		heartbeat({
			agent: agentName,
			elapsedSeconds: elapsed,
			attempt: attemptNumber,
		});
	}, HEARTBEAT_INTERVAL_MS);

	try {
		const logger = createActivityLogger();

		// 1. Build session metadata and get/create container
		const sessionMetadata = buildSessionMetadata(input);
		const container = getOrCreateContainer(
			workflowId,
			sessionMetadata,
			buildContainerConfig(input),
		);

		// 2. Create audit session for THIS agent execution
		// NOTE: Each agent needs its own AuditSession because AuditSession uses
		// instance state (currentAgentName) that cannot be shared across parallel agents
		const auditSession = new AuditSession(sessionMetadata);
		await auditSession.initialize(workflowId);

		// 3. Execute agent via service (throws PentestError on failure)
		const deliverablesPath = deliverablesDir(
			repoPath,
			container.config.deliverablesSubdir,
		);
		const endResult = await container.agentExecution.executeOrThrow(
			agentName,
			{
				webUrl,
				repoPath,
				deliverablesPath,
				configPath,
				attemptNumber,
				...(input.apiKey !== undefined && { apiKey: input.apiKey }),
				...(input.providerConfig !== undefined && {
					providerConfig: input.providerConfig,
				}),
				...(input.promptDir !== undefined && {
					promptDir: path.isAbsolute(input.promptDir)
						? input.promptDir
						: path.resolve(
								process.env.STORRON_WORKER_ROOT ?? process.cwd(),
								input.promptDir,
							),
				}),
				...(input.configYAML !== undefined && { configYAML: input.configYAML }),
			},
			auditSession,
			logger,
			container,
		);

		// 4. Return metrics. Token counts and turn count are sourced from the SDK's
		//    final result message via the executor layer; falling back to null when
		//    the SDK omitted them (older SDK versions or unrecognized response shapes).
		return {
			durationMs: Date.now() - startTime,
			inputTokens: endResult.input_tokens ?? null,
			outputTokens: endResult.output_tokens ?? null,
			numTurns: endResult.num_turns ?? null,
			model: endResult.model,
		};
	} catch (error) {
		// If error is already an ApplicationFailure, re-throw directly
		if (error instanceof ApplicationFailure) {
			throw error;
		}

		// Check if output validation retry limit reached (PentestError with code)
		if (
			error instanceof PentestError &&
			error.code === ErrorCode.OUTPUT_VALIDATION_FAILED &&
			attemptNumber >= MAX_OUTPUT_VALIDATION_RETRIES
		) {
			throw ApplicationFailure.nonRetryable(
				`Agent ${agentName} failed output validation after ${attemptNumber} attempts`,
				"OutputValidationError",
				[{ agentName, attemptNumber, elapsed: Date.now() - startTime }],
			);
		}

		// Classify error for Temporal retry behavior
		const classified = classifyErrorForTemporal(error);
		const rawMessage = error instanceof Error ? error.message : String(error);
		const message = truncateErrorMessage(rawMessage);

		if (classified.retryable) {
			const failure = ApplicationFailure.create({
				message,
				type: classified.type,
				details: [
					{ agentName, attemptNumber, elapsed: Date.now() - startTime },
				],
			});
			truncateStackTrace(failure);
			throw failure;
		} else {
			const failure = ApplicationFailure.nonRetryable(
				message,
				classified.type,
				[{ agentName, attemptNumber, elapsed: Date.now() - startTime }],
			);
			truncateStackTrace(failure);
			throw failure;
		}
	} finally {
		clearInterval(heartbeatInterval);
	}
}
