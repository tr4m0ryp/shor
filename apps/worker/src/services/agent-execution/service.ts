// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent Execution Service
 *
 * Handles the full agent lifecycle:
 * - Load config via ConfigLoaderService
 * - Load prompt template using AGENTS[agentName].promptTemplate
 * - Create git checkpoint
 * - Start audit logging
 * - Invoke Claude SDK via runClaudePrompt
 * - Spending cap check using isSpendingCapBehavior
 * - Handle failure (rollback, audit)
 * - Validate output using AGENTS[agentName].deliverableFilename
 * - Commit on success, log metrics
 *
 * No Temporal dependencies - pure domain logic.
 */

import { path } from "zx";
import {
	type ClaudePromptResult,
	runClaudePrompt,
} from "../../ai/claude-executor.js";
import { getOutputFormat } from "../../ai/queue-schemas.js";
import type { AuditSession } from "../../audit/index.js";
import { AGENTS } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import type { AgentEndResult } from "../../types/audit.js";
import type { AgentMetrics } from "../../types/metrics.js";
import { isErr, type Result } from "../../types/result.js";
import type { ConfigLoaderService } from "../config-loader.js";
import type { Container } from "../container.js";
import type { PentestError } from "../error-handling.js";
import { runWithCoverage } from "./coverage-loop.js";
import {
	checkSpendingCap,
	failOnHardMissing,
	finalizeSuccess,
	handleExecutionFailure,
	validateDeliverable,
	writeStructuredOutput,
} from "./post-execution.js";
import { runPreExecution } from "./pre-execution.js";
import type { AgentExecutionInput } from "./types.js";

/**
 * Service for executing agents with full lifecycle management.
 *
 * NOTE: AuditSession is passed per-execution, NOT stored on the service.
 * This is critical for parallel agent execution - each agent needs its own
 * AuditSession instance because AuditSession uses instance state (currentAgentName)
 * to track which agent is currently logging.
 */
export class AgentExecutionService {
	private readonly configLoader: ConfigLoaderService;

	constructor(configLoader: ConfigLoaderService) {
		this.configLoader = configLoader;
	}

	/**
	 * Execute an agent with full lifecycle management.
	 *
	 * @param agentName - Name of the agent to execute
	 * @param input - Execution input parameters
	 * @param auditSession - Audit session for this specific agent execution
	 * @param logger - Structured activity logger
	 * @param container - Optional DI container threaded through to pre-execution.
	 * @returns Result containing AgentEndResult on success, PentestError on failure
	 */
	async execute(
		agentName: AgentName,
		input: AgentExecutionInput,
		auditSession: AuditSession,
		logger: ActivityLogger,
		container?: Container,
	): Promise<Result<AgentEndResult, PentestError>> {
		const {
			webUrl,
			repoPath,
			deliverablesPath,
			configPath,
			configData,
			configYAML,
			attemptNumber,
			apiKey,
			promptDir,
			providerConfig,
		} = input;

		// 1-4. Pre-execution stages (config, prompt, git checkpoint, audit start)
		const preExecution = await runPreExecution(
			this.configLoader,
			agentName,
			webUrl,
			repoPath,
			deliverablesPath,
			attemptNumber,
			configPath,
			configData,
			configYAML,
			promptDir,
			logger,
			container,
			auditSession,
		);
		if (isErr(preExecution)) {
			return preExecution;
		}
		const { prompt } = preExecution.value;

		// 5. Execute agent — with the coverage continuation loop. Round 0 is the
		// normal one-shot run; if the agent stayed below its tool-breadth floor
		// and rounds + budget remain, the same agent is re-invoked with a compact
		// follow-up naming the untried tools (skillTracker accumulates usage
		// across rounds). `outcome.result` is the FINAL round; steps 6/9/10 then
		// run once on the converged state, unchanged.
		const outputFormat = getOutputFormat(agentName);
		const deliverablesSubdir = path.relative(repoPath, deliverablesPath);
		const outcome = await runWithCoverage({
			agentName,
			basePrompt: prompt,
			deliverablesSubdir,
			logger,
			auditSession,
			runRound: (roundPrompt) =>
				runClaudePrompt(
					roundPrompt,
					repoPath,
					"", // context
					agentName, // description
					agentName,
					auditSession,
					logger,
					AGENTS[agentName].modelTier,
					outputFormat,
					apiKey,
					deliverablesSubdir,
					providerConfig,
					undefined,
				),
		});
		const result: ClaudePromptResult = outcome.result;

		// 6. Spending cap check - defense-in-depth
		const capResult = await checkSpendingCap(
			agentName,
			deliverablesPath,
			auditSession,
			logger,
			attemptNumber,
			result,
		);
		if (capResult) {
			return capResult;
		}

		// 6b. Model refusal check - defense-in-depth. A safety refusal returns as
		// a "successful" short result; catch it so it retries under the
		// authorization preamble instead of passing through as "no findings".
		const refusalResult = await checkRefusal(
			agentName,
			deliverablesPath,
			auditSession,
			logger,
			attemptNumber,
			result,
		);
		if (refusalResult) {
			return refusalResult;
		}

		// 7. Handle execution failure
		if (!result.success) {
			return handleExecutionFailure(
				agentName,
				deliverablesPath,
				auditSession,
				logger,
				attemptNumber,
				result,
			);
		}

		// 8. Write structured output to disk (vuln agents only)
		await writeStructuredOutput(agentName, deliverablesPath, result, logger);

		// 9. Validate output
		const validationFailure = await validateDeliverable(
			agentName,
			deliverablesPath,
			auditSession,
			logger,
			attemptNumber,
			result,
		);
		if (validationFailure) {
			return validationFailure;
		}

		// 9b. Last-resort coverage bridge (T4). If a REQUIRED tool was still not
		// exercised after the final continuation round, surface a retryable
		// OUTPUT_VALIDATION_FAILED via the existing failAgent machinery rather
		// than inventing a new retry path. Dormant under the default policy
		// (required = [] for every agent → hardMissing always empty), but wired
		// so tightening a policy later needs no new plumbing.
		const hardMissFailure = await failOnHardMissing(
			agentName,
			deliverablesPath,
			auditSession,
			logger,
			attemptNumber,
			result,
			outcome.coverage,
		);
		if (hardMissFailure) {
			return hardMissFailure;
		}

		// 10. Success - commit deliverables, then capture checkpoint hash
		return finalizeSuccess(
			agentName,
			deliverablesPath,
			auditSession,
			logger,
			attemptNumber,
			result,
		);
	}

	/**
	 * Execute an agent, throwing PentestError on failure.
	 *
	 * Preferred for Temporal activities so the activity layer can catch errors
	 * and classify them into `ApplicationFailure` without importing Result.
	 * Forwards `container` to `execute`.
	 */
	async executeOrThrow(
		agentName: AgentName,
		input: AgentExecutionInput,
		auditSession: AuditSession,
		logger: ActivityLogger,
		container?: Container,
	): Promise<AgentEndResult> {
		const result = await this.execute(
			agentName,
			input,
			auditSession,
			logger,
			container,
		);
		if (isErr(result)) {
			throw result.error;
		}
		return result.value;
	}

	/**
	 * Convert AgentEndResult to AgentMetrics for workflow state.
	 */
	static toMetrics(
		endResult: AgentEndResult,
		result: ClaudePromptResult,
	): AgentMetrics {
		return {
			durationMs: endResult.duration_ms,
			inputTokens: result.inputTokens ?? endResult.input_tokens ?? null,
			outputTokens: result.outputTokens ?? endResult.output_tokens ?? null,
			numTurns: result.turns ?? endResult.num_turns ?? null,
			model: result.model,
		};
	}
}
