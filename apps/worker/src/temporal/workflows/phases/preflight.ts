// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Preflight phase: cheap validation + deliverables-git initialisation.
 *
 * Runs before any agent work commits expensive activity time. Validation
 * does not produce `AgentMetrics`, so it deliberately bypasses the
 * sequential-phase helper.
 */

import { log } from "@temporalio/workflow";
import type { PipelineContext } from "../pipeline-context.js";
import { waitIfPaused } from "../pipeline-context.js";

/**
 * Run preflight validation and initialise the deliverables git workspace.
 * Mutates `ctx.state` to record the current phase.
 */
export async function runPreflightPhase(ctx: PipelineContext): Promise<void> {
	await waitIfPaused(ctx);

	// === Preflight Validation ===
	// Quick sanity checks before committing to expensive agent runs.
	// NOT using runSequentialPhase — preflight doesn't produce AgentMetrics.
	ctx.state.currentPhase = "preflight";
	ctx.state.currentAgent = null;
	await ctx.proxies.preflightActs.runPreflightValidation(ctx.activityInput);
	log.info("Preflight validation passed");

	// === Initialize Deliverables Git ===
	await ctx.a.initDeliverableGit(ctx.activityInput);
}
