// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
