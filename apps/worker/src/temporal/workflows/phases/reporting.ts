// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Reporting phase: assemble the final executive-level security report.
 *
 * Concatenates exploitation evidence, runs the report agent for the executive
 * summary and cleanup pass, then injects model metadata. Skipped entirely
 * when resuming a workspace where the report agent already finished.
 */

import { log } from "@temporalio/workflow";
import type { PipelineContext } from "../pipeline-context.js";
import { shouldSkip, waitIfPaused } from "../pipeline-context.js";

/**
 * Run the reporting phase or short-circuit if already complete on resume.
 * Mutates `ctx.state` to record the report agent run and updates the
 * checkpoint when checkpointing is enabled.
 */
export async function runReportingPhase(ctx: PipelineContext): Promise<void> {
	const { a, activityInput, input, state } = ctx;

	// === Phase 5: Reporting ===
	if (!shouldSkip(ctx, "report")) {
		await waitIfPaused(ctx);
		state.currentPhase = "reporting";
		state.currentAgent = "report";
		await a.logPhaseTransition(activityInput, "reporting", "start");

		// First, assemble the concatenated report from exploitation evidence files
		await a.assembleReportActivity(activityInput);

		// Then run the report agent to add executive summary and clean up
		state.agentMetrics.report = await a.runReportAgent(activityInput);
		state.completedAgents.push("report");
		if (input.checkpointsEnabled) {
			await a.saveCheckpoint(activityInput, "report", "reporting", state);
		}

		// Inject model metadata into the final report
		await a.injectReportMetadataActivity(activityInput);

		await a.logPhaseTransition(activityInput, "reporting", "complete");
	} else {
		log.info("Skipping report (already complete)");
		state.completedAgents.push("report");
	}
}
