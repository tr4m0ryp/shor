// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal workflow for Storron pentest pipeline.
 *
 * Orchestrates the penetration testing workflow:
 * 1. Pre-Reconnaissance (sequential)
 * 2. Reconnaissance (sequential)
 * 3-4. Vulnerability + Exploitation (5 pipelined pairs in parallel)
 *      Each pair: vuln agent → queue check → conditional exploit
 *      No synchronization barrier - exploits start when their vuln finishes
 * 5. Reporting (sequential)
 *
 * Features:
 * - Queryable state via getProgress
 * - Automatic retry with backoff for transient/billing errors
 * - Non-retryable classification for permanent errors
 * - Audit correlation via workflowId
 * - Graceful failure handling: pipelines continue if one fails
 */

import {
	ApplicationFailure,
	isCancellation,
	log,
	setHandler,
	workflowInfo,
} from "@temporalio/workflow";
import {
	getProgress,
	type PipelineInput,
	type PipelineProgress,
	type PipelineState,
	pauseWorkflow,
	resumeWorkflow,
} from "../shared.js";
import { toWorkflowSummary } from "../summary-mapper.js";
import { classifyErrorCode, formatWorkflowError } from "../workflow-errors.js";
import { runPreflightPhase } from "./phases/preflight.js";
import { runReportingPhase } from "./phases/reporting.js";
import { runSequentialPhase } from "./phases/sequential.js";
import { runVulnExploitPhase } from "./phases/vuln-exploit.js";
import {
	buildActivityInput,
	buildActivityProxies,
	type PipelineContext,
	selectActivityProxy,
} from "./pipeline-context.js";
import { maybeResume } from "./resume.js";
import { computeSummary, createInitialState } from "./state.js";

/**
 * Validate the input repoPath: reject traversal attempts and require absolute path.
 * Throws a non-retryable ApplicationFailure so misconfigured runs fail fast.
 */
function validateInput(input: PipelineInput): void {
	if (!input.repoPath || input.repoPath.includes("..")) {
		throw ApplicationFailure.nonRetryable(
			`Invalid repoPath: path traversal not allowed (received: ${input.repoPath ?? "<empty>"})`,
			"ConfigurationError",
		);
	}
	if (!input.repoPath.startsWith("/")) {
		throw ApplicationFailure.nonRetryable(
			`Invalid repoPath: absolute path required (received: ${input.repoPath})`,
			"ConfigurationError",
		);
	}
}

/** Register query and signal handlers that drive the dashboard + control flow. */
function registerHandlers(ctx: PipelineContext): void {
	const { state, workflowId } = ctx;

	setHandler(
		getProgress,
		(): PipelineProgress => ({
			...state,
			workflowId,
			elapsedMs: Date.now() - state.startTime,
		}),
	);

	setHandler(pauseWorkflow, () => {
		if (!state.paused) {
			state.paused = true;
			state.pausedAt = Date.now();
			log.info("Pause requested");
		}
	});

	setHandler(resumeWorkflow, () => {
		if (state.paused) {
			state.paused = false;
			state.pausedAt = null;
			log.info("Resume requested");
		}
	});
}

/**
 * Core pipeline orchestration. Coordinates the pentest pipeline stages.
 *
 * IMPORTANT: This function uses Temporal workflow APIs internally (proxyActivities,
 * queries). It can ONLY be called from within a Temporal workflow execution.
 * Do not call from standalone scripts or activity code.
 */
export async function pentestPipeline(
	input: PipelineInput,
): Promise<PipelineState> {
	validateInput(input);

	const { workflowId } = workflowInfo();
	const proxies = buildActivityProxies(input);
	const a = selectActivityProxy(input, proxies);
	const activityInput = buildActivityInput(input, workflowId);
	const state = createInitialState();

	const ctx: PipelineContext = {
		input,
		workflowId,
		state,
		activityInput,
		proxies,
		a,
		resumeState: null,
	};

	registerHandlers(ctx);

	const resumeOutcome = await maybeResume(ctx);
	ctx.resumeState = resumeOutcome.resumeState;
	if (resumeOutcome.shortCircuited) {
		return state;
	}

	try {
		// === Preflight Validation + Deliverables Git Init ===
		await runPreflightPhase(ctx);

		// === Phase 1: Pre-Reconnaissance ===
		await runSequentialPhase(
			ctx,
			"pre-recon",
			"pre-recon",
			ctx.a.runPreReconAgent,
		);

		// === Phase 2: Reconnaissance ===
		await runSequentialPhase(ctx, "recon", "recon", ctx.a.runReconAgent);

		// === Phases 3-4: Vulnerability Analysis + Exploitation (Pipelined) ===
		await runVulnExploitPhase(ctx);

		// === Phase 5: Reporting ===
		await runReportingPhase(ctx);

		// === Phase 6: Attack-Surface Synthesis ===
		// Runs once after reporting. Converts the merged findings + proven
		// exploits into scenario JSON + Markdown with ready-to-paste Claude Code
		// prompts. Operators can short-circuit the phase via the
		// STORRON_DISABLE_ATTACK_SURFACE=1 env var, handled inside the activity.
		await runSequentialPhase(
			ctx,
			"attack-surface",
			"attack-surface",
			ctx.a.runAttackSurfaceAgent,
		);

		state.status = "completed";
		state.currentPhase = null;
		state.currentAgent = null;
		state.summary = computeSummary(state);

		// Log workflow completion summary
		await ctx.a.logWorkflowComplete(
			activityInput,
			toWorkflowSummary(state, "completed"),
		);

		return state;
	} catch (error) {
		// Cancellation: return structured state instead of throwing
		if (isCancellation(error)) {
			state.status = "cancelled";
			state.error = `Cancelled during phase: ${state.currentPhase ?? "unknown"}`;
			state.summary = computeSummary(state);
			await ctx.a.logWorkflowComplete(
				activityInput,
				toWorkflowSummary(state, "cancelled"),
			);
			return state;
		}

		state.status = "failed";
		state.failedAgent = state.currentAgent;
		state.error = formatWorkflowError(
			error,
			state.currentPhase,
			state.currentAgent,
		);
		const errorCode = classifyErrorCode(error);
		if (errorCode) {
			state.errorCode = errorCode;
		}
		state.summary = computeSummary(state);

		// Log workflow failure summary
		await ctx.a.logWorkflowComplete(
			activityInput,
			toWorkflowSummary(state, "failed"),
		);

		throw error;
	}
}

/** OSS workflow entry point — thin shell around the extracted pipeline function. */
export async function pentestPipelineWorkflow(
	input: PipelineInput,
): Promise<PipelineState> {
	return pentestPipeline(input);
}
