// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Audit-log activities and workflow-level checkpoint persistence.
 *
 * Phase transitions, workflow completion entries, and the DI-backed
 * `saveCheckpoint` hook all live here because they share session-metadata
 * plumbing and run outside the agent-execution path.
 */

import { AuditSession } from "../../audit/index.js";
import type { WorkflowSummary } from "../../audit/workflow-logger.js";
import { getContainer, removeContainer } from "../../services/container.js";
import type { PipelineState } from "../shared.js";
import { buildSessionMetadata } from "./_internal.js";
import type { ActivityInput } from "./types.js";

/**
 * Log phase transition to the unified workflow log.
 */
export async function logPhaseTransition(
	input: ActivityInput,
	phase: string,
	event: "start" | "complete",
): Promise<void> {
	const sessionMetadata = buildSessionMetadata(input);
	const auditSession = new AuditSession(sessionMetadata);
	await auditSession.initialize(input.workflowId);

	if (event === "start") {
		await auditSession.logPhaseStart(phase);
	} else {
		await auditSession.logPhaseComplete(phase);
	}
}

/**
 * Log workflow completion with full summary.
 * Cleans up container when done.
 */
export async function logWorkflowComplete(
	input: ActivityInput,
	summary: WorkflowSummary,
): Promise<void> {
	const { workflowId } = input;
	const sessionMetadata = buildSessionMetadata(input);

	// 1. Initialize audit session and mark final status
	const auditSession = new AuditSession(sessionMetadata);
	await auditSession.initialize(workflowId);
	await auditSession.updateSessionStatus(summary.status);

	// 2. Load cumulative metrics from session.json
	const sessionData = (await auditSession.getMetrics()) as {
		metrics: {
			total_duration_ms: number;
			agents: Record<string, { final_duration_ms: number }>;
		};
	};

	// 3. Fill in metrics for skipped agents (resumed from previous run)
	const agentMetrics = { ...summary.agentMetrics };
	for (const agentName of summary.completedAgents) {
		if (!agentMetrics[agentName]) {
			const agentData = sessionData.metrics.agents[agentName];
			if (agentData) {
				agentMetrics[agentName] = {
					durationMs: agentData.final_duration_ms,
				};
			}
		}
	}

	// 4. Build cumulative summary with cross-run totals
	const cumulativeSummary: WorkflowSummary = {
		...summary,
		totalDurationMs: sessionData.metrics.total_duration_ms,
		agentMetrics,
	};

	// 5. Write completion entry to workflow.log
	await auditSession.logWorkflowComplete(cumulativeSummary);

	// 6. Clean up container
	removeContainer(workflowId);
}

/**
 * Persist pipeline state after an agent completes.
 *
 * Delegates to the CheckpointProvider registered in the DI container.
 * Default: no-op. Consumers can override this activity at the worker level with custom persistence.
 */
export async function saveCheckpoint(
	input: ActivityInput,
	agentName: string,
	phase: string,
	state: PipelineState,
): Promise<void> {
	const container = getContainer(input.workflowId);
	if (!container?.checkpointProvider) return;
	return container.checkpointProvider.onAgentComplete(agentName, phase, state);
}
