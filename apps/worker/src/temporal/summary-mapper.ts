// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Maps PipelineState to WorkflowSummary for audit logging.
 * Pure function with no side effects.
 */

import type { WorkflowSummary } from "../audit/workflow-logger.js";
import type { PipelineState } from "./shared.js";

/**
 * Maps PipelineState to WorkflowSummary.
 *
 * This function is deterministic (no Date.now() or I/O) so it can be
 * safely imported into Temporal workflows. The caller must ensure
 * state.summary is set before calling (via computeSummary).
 */
export function toWorkflowSummary(
	state: PipelineState,
	status: "completed" | "failed" | "cancelled",
): WorkflowSummary {
	// state.summary must be computed before calling this mapper
	const summary = state.summary;
	if (!summary) {
		throw new Error(
			"toWorkflowSummary: state.summary must be set before calling",
		);
	}

	return {
		status,
		totalDurationMs: summary.totalDurationMs,
		completedAgents: state.completedAgents,
		agentMetrics: Object.fromEntries(
			Object.entries(state.agentMetrics).map(([name, m]) => [
				name,
				{ durationMs: m.durationMs },
			]),
		),
		...(state.error && { error: state.error }),
	};
}
