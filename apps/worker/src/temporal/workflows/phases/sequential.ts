// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Generic sequential-phase runner.
 *
 * Used by phases that execute a single agent end-to-end: pre-recon, recon,
 * and attack-surface. The helper handles resume-aware skipping, phase
 * transition logging, metric capture, and optional checkpointing.
 */

import { log } from "@temporalio/workflow";
import type { AgentName } from "../../../types/agents.js";
import type { ActivityInput } from "../../activities.js";
import type { AgentMetrics } from "../../shared.js";
import type { PipelineContext } from "../pipeline-context.js";
import { shouldSkip, waitIfPaused } from "../pipeline-context.js";

/**
 * Run a sequential agent phase (pre-recon, recon, attack-surface).
 *
 * Mutates `ctx.state` to track current phase/agent and records the agent
 * once it completes successfully. Skips the agent entirely when resuming
 * from a workspace where it already ran.
 */
export async function runSequentialPhase(
	ctx: PipelineContext,
	phaseName: string,
	agentName: AgentName,
	runAgent: (input: ActivityInput) => Promise<AgentMetrics>,
): Promise<void> {
	await waitIfPaused(ctx);

	if (!shouldSkip(ctx, agentName)) {
		ctx.state.currentPhase = phaseName;
		ctx.state.currentAgent = agentName;
		await ctx.a.logPhaseTransition(ctx.activityInput, phaseName, "start");
		ctx.state.agentMetrics[agentName] = await runAgent(ctx.activityInput);
		ctx.state.completedAgents.push(agentName);
		if (ctx.input.checkpointsEnabled) {
			await ctx.a.saveCheckpoint(
				ctx.activityInput,
				agentName,
				phaseName,
				ctx.state,
			);
		}
		await ctx.a.logPhaseTransition(ctx.activityInput, phaseName, "complete");
	} else {
		log.info(`Skipping ${agentName} (already complete)`);
		ctx.state.completedAgents.push(agentName);
	}
}
