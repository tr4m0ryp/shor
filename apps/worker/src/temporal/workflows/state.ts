// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pipeline state helpers for the Storron pentest workflow.
 *
 * Houses pure functions that read or transform `PipelineState`. No Temporal
 * workflow APIs are imported here so the module stays sandbox-safe and easy
 * to reason about.
 */

import type { PipelineState, PipelineSummary } from "../shared.js";

/**
 * Compute aggregated metrics from the current pipeline state.
 * Called on both success and failure to provide partial metrics.
 */
export function computeSummary(state: PipelineState): PipelineSummary {
	const metrics = Object.values(state.agentMetrics);
	return {
		totalDurationMs: Date.now() - state.startTime,
		totalTurns: metrics.reduce((sum, m) => sum + (m.numTurns ?? 0), 0),
		agentCount: state.completedAgents.length,
	};
}

/**
 * Create the initial pipeline state for a fresh workflow execution.
 * `startTime` uses `Date.now()` which Temporal records deterministically in
 * the workflow event history.
 */
export function createInitialState(): PipelineState {
	return {
		status: "running",
		currentPhase: null,
		currentAgent: null,
		paused: false,
		pausedAt: null,
		completedAgents: [],
		failedAgent: null,
		error: null,
		startTime: Date.now(),
		agentMetrics: {},
		summary: null,
	};
}
