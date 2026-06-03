// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Reconnaissance phase runner.
 *
 * Default path (flag OFF): a thin pass-through to `runSequentialPhase`, so recon
 * dispatch is byte-identical to running the single recon agent inline. The
 * `reconFanout` flag MUST default off — when it is unset/false this module adds
 * ZERO extra activity calls and the workflow history is unchanged.
 *
 * Fan-out path (flag ON, opt-in / power-user, heavier + costlier): decompose
 * recon into one parallel sub-run per recommended tool so coverage is guaranteed
 * by construction instead of by the post-hoc coverage gate. The tool set is
 * resolved in an ACTIVITY (`resolveReconCandidates`) so the workflow only ever
 * sees a recorded list and stays replay-deterministic — no env/Math/Date reads
 * in workflow scope. The existing per-host rate limits and the worker task-queue
 * concurrency still bound real parallelism; `max_concurrent_pipelines` caps the
 * fan-out width here too.
 *
 * EXPERIMENTAL GAP (deliberate): the fan-out path does NOT yet consolidate the
 * per-tool deliverables back into the single canonical `recon_deliverable.md`
 * that downstream exploit prompts read. That synthesis is a follow-up; the
 * fan-out path is therefore unreachable by default and is not production-ready.
 */

import { log } from "@temporalio/workflow";
import type { AgentMetrics } from "../../shared.js";
import type { PipelineContext } from "../pipeline-context.js";
import { shouldSkip, waitIfPaused } from "../pipeline-context.js";
import { runSequentialPhase } from "./sequential.js";

const RECON_PHASE = "recon";
const RECON_AGENT = "recon";

/**
 * Run thunks with a concurrency limit, returning a settled result per thunk.
 * Mirrors the vuln/exploit limiter: when `limit >= thunks.length` everything
 * launches at once. Results are in completion order — callers must not rely on
 * input order.
 */
async function runWithConcurrencyLimit(
	thunks: Array<() => Promise<AgentMetrics>>,
	limit: number,
): Promise<PromiseSettledResult<AgentMetrics>[]> {
	const results: PromiseSettledResult<AgentMetrics>[] = [];
	const inFlight = new Set<Promise<void>>();

	for (const thunk of thunks) {
		const slot = thunk()
			.then(
				(value) => {
					results.push({ status: "fulfilled", value });
				},
				(reason: unknown) => {
					results.push({ status: "rejected", reason });
				},
			)
			.finally(() => {
				inFlight.delete(slot);
			});

		inFlight.add(slot);

		if (inFlight.size >= limit) {
			await Promise.race(inFlight);
		}
	}

	await Promise.allSettled(inFlight);
	return results;
}

/** Fold per-tool sub-run metrics into one aggregate recon metric. */
function aggregateMetrics(parts: AgentMetrics[]): AgentMetrics {
	const sumNullable = (pick: (m: AgentMetrics) => number | null): number | null => {
		const present = parts.map(pick).filter((v): v is number => v !== null);
		return present.length > 0 ? present.reduce((a, b) => a + b, 0) : null;
	};
	return {
		durationMs: parts.reduce((a, m) => a + m.durationMs, 0),
		inputTokens: sumNullable((m) => m.inputTokens),
		outputTokens: sumNullable((m) => m.outputTokens),
		numTurns: sumNullable((m) => m.numTurns),
		model: parts.find((m) => m.model !== undefined)?.model,
	};
}

/**
 * Fan recon out into one sub-run per recommended tool.
 *
 * Foundational phase: if ANY sub-run fails we rethrow the first failure so the
 * workflow fails loudly rather than proceeding on a partial map.
 */
async function runReconFanout(ctx: PipelineContext): Promise<void> {
	const { a, activityInput, input, state } = ctx;

	state.currentPhase = RECON_PHASE;
	state.currentAgent = RECON_AGENT;
	await a.logPhaseTransition(activityInput, RECON_PHASE, "start");

	const tools = await a.resolveReconCandidates();
	if (tools.length === 0) {
		// No candidate pool → nothing to fan out; behave like the single agent.
		state.agentMetrics[RECON_AGENT] = await a.runReconAgent(activityInput);
		state.completedAgents.push(RECON_AGENT);
		await a.logPhaseTransition(activityInput, RECON_PHASE, "complete");
		return;
	}

	log.info(`Recon fan-out: ${tools.length} per-tool sub-run(s)`, { tools });
	const limit = input.pipelineConfig?.max_concurrent_pipelines ?? tools.length;
	const thunks = tools.map(
		(tool) => () => a.runReconToolSubrun(activityInput, tool),
	);
	const settled = await runWithConcurrencyLimit(thunks, limit);

	const metrics: AgentMetrics[] = [];
	for (const r of settled) {
		if (r.status === "fulfilled") metrics.push(r.value);
		else throw r.reason;
	}

	state.agentMetrics[RECON_AGENT] = aggregateMetrics(metrics);
	state.completedAgents.push(RECON_AGENT);
	if (input.checkpointsEnabled) {
		await a.saveCheckpoint(activityInput, RECON_AGENT, RECON_PHASE, state);
	}
	await a.logPhaseTransition(activityInput, RECON_PHASE, "complete");
}

/**
 * Run the reconnaissance phase.
 *
 * Flag OFF (default): identical to `runSequentialPhase(ctx, "recon", "recon",
 * runReconAgent)`. Flag ON: fan out per recommended tool (see module header).
 */
export async function runReconPhase(ctx: PipelineContext): Promise<void> {
	if (!ctx.input.reconFanout) {
		await runSequentialPhase(ctx, RECON_PHASE, RECON_AGENT, ctx.a.runReconAgent);
		return;
	}

	await waitIfPaused(ctx);
	if (shouldSkip(ctx, RECON_AGENT)) {
		log.info(`Skipping ${RECON_AGENT} (already complete)`);
		ctx.state.completedAgents.push(RECON_AGENT);
		return;
	}
	await runReconFanout(ctx);
}
