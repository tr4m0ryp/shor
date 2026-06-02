// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
