// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
