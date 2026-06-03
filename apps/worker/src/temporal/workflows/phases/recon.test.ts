// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Recon-phase dispatch tests.
 *
 * The load-bearing assertion is the flag-OFF case: recon must dispatch exactly
 * as it does today (the single recon agent, once, with NO fan-out activity
 * calls). The flag-ON case is covered too so the gate is pinned both ways.
 *
 * `@temporalio/workflow`'s `log` throws outside a workflow context, so it is
 * stubbed; every activity the phase touches is a spy on a fake proxy.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@temporalio/workflow", () => ({
	log: { info: vi.fn(), warn: vi.fn() },
	condition: vi.fn(),
}));

import type { AgentMetrics } from "../../shared.js";
import type { PipelineContext } from "../pipeline-context.js";
import { runReconPhase } from "./recon.js";

const METRIC: AgentMetrics = {
	durationMs: 10,
	inputTokens: 1,
	outputTokens: 2,
	numTurns: 3,
	model: "test-model",
};

/** Activity spies for every activity the recon phase may invoke. */
function makeActivitySpies() {
	return {
		runReconAgent: vi.fn(async () => METRIC),
		logPhaseTransition: vi.fn(async () => {}),
		saveCheckpoint: vi.fn(async () => {}),
		resolveReconCandidates: vi.fn(async () => ["httpx", "nmap", "katana"]),
		runReconToolSubrun: vi.fn(async () => METRIC),
	};
}

/** Build a minimal PipelineContext over the activity spies. */
function makeCtx(
	a: ReturnType<typeof makeActivitySpies>,
	reconFanout?: boolean,
): PipelineContext {
	return {
		input: {
			webUrl: "http://t",
			repoPath: "/r",
			...(reconFanout !== undefined && { reconFanout }),
		},
		workflowId: "wf-1",
		state: {
			status: "running",
			currentPhase: null,
			currentAgent: null,
			paused: false,
			pausedAt: null,
			completedAgents: [],
			failedAgent: null,
			error: null,
			startTime: 0,
			agentMetrics: {},
			summary: null,
		},
		activityInput: { webUrl: "http://t", repoPath: "/r", workflowId: "wf-1", sessionId: "s" },
		// Only the activity proxy `a` is exercised by the phase under test.
		proxies: {} as PipelineContext["proxies"],
		a: a as unknown as PipelineContext["a"],
		resumeState: null,
	};
}

describe("runReconPhase — flag OFF (default, must match today)", () => {
	let a: ReturnType<typeof makeActivitySpies>;

	beforeEach(() => {
		a = makeActivitySpies();
	});

	it("dispatches the single recon agent exactly once", async () => {
		await runReconPhase(makeCtx(a, false));
		expect(a.runReconAgent).toHaveBeenCalledTimes(1);
	});

	it("never invokes any fan-out activity", async () => {
		await runReconPhase(makeCtx(a, false));
		expect(a.resolveReconCandidates).not.toHaveBeenCalled();
		expect(a.runReconToolSubrun).not.toHaveBeenCalled();
	});

	it("records recon metrics and completion identically to the sequential phase", async () => {
		const ctx = makeCtx(a, false);
		await runReconPhase(ctx);
		expect(ctx.state.agentMetrics.recon).toEqual(METRIC);
		expect(ctx.state.completedAgents).toEqual(["recon"]);
	});

	it("treats reconFanout absent the same as off", async () => {
		// No reconFanout key at all — the production default.
		const ctx = makeCtx(a);
		await runReconPhase(ctx);
		expect(a.runReconAgent).toHaveBeenCalledTimes(1);
		expect(a.resolveReconCandidates).not.toHaveBeenCalled();
	});

	it("logs phase start and complete via the activity proxy", async () => {
		await runReconPhase(makeCtx(a, false));
		expect(a.logPhaseTransition).toHaveBeenCalledWith(
			expect.anything(),
			"recon",
			"start",
		);
		expect(a.logPhaseTransition).toHaveBeenCalledWith(
			expect.anything(),
			"recon",
			"complete",
		);
	});
});

describe("runReconPhase — flag ON (opt-in fan-out)", () => {
	let a: ReturnType<typeof makeActivitySpies>;

	beforeEach(() => {
		a = makeActivitySpies();
	});

	it("fans out one sub-run per resolved candidate and skips the single agent", async () => {
		await runReconPhase(makeCtx(a, true));
		expect(a.resolveReconCandidates).toHaveBeenCalledTimes(1);
		expect(a.runReconToolSubrun).toHaveBeenCalledTimes(3);
		expect(a.runReconAgent).not.toHaveBeenCalled();
	});

	it("records an aggregate recon metric and marks recon complete", async () => {
		const ctx = makeCtx(a, true);
		await runReconPhase(ctx);
		// 3 sub-runs aggregated: durations sum, model carried through.
		const recon = ctx.state.agentMetrics.recon;
		expect(recon).toBeDefined();
		expect(recon?.durationMs).toBe(30);
		expect(recon?.model).toBe("test-model");
		expect(ctx.state.completedAgents).toEqual(["recon"]);
	});

	it("falls back to the single agent when no candidates resolve", async () => {
		a.resolveReconCandidates.mockResolvedValueOnce([]);
		await runReconPhase(makeCtx(a, true));
		expect(a.runReconToolSubrun).not.toHaveBeenCalled();
		expect(a.runReconAgent).toHaveBeenCalledTimes(1);
	});
});
