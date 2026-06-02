// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { formatDuration, formatTimestamp } from "../../utils/formatting.js";
import type { SessionMetadata } from "../utils.js";
import { formatErrorBlock } from "./formatters.js";
import type { WorkflowSummary } from "./types.js";

/** Banner shown at the top of a fresh workflow log file. */
export function buildInitHeader(
	workflowId: string | undefined,
	sessionMetadata: SessionMetadata,
): string {
	return [
		`================================================================================`,
		`Storron Pentest - Workflow Log`,
		`================================================================================`,
		`Workflow ID: ${workflowId ?? sessionMetadata.id}`,
		`Target URL:  ${sessionMetadata.webUrl}`,
		`Started:     ${formatTimestamp()}`,
		`================================================================================`,
		``,
	].join("\n");
}

/** Banner inserted into the log when a workflow is resumed from a checkpoint. */
export function buildResumeHeader(resumeInfo: {
	previousWorkflowId: string;
	newWorkflowId: string;
	checkpointHash: string;
	completedAgents: string[];
}): string {
	return [
		``,
		`================================================================================`,
		`RESUMED`,
		`================================================================================`,
		`Previous Workflow ID: ${resumeInfo.previousWorkflowId}`,
		`New Workflow ID:      ${resumeInfo.newWorkflowId}`,
		`Resumed At:           ${formatTimestamp()}`,
		`Checkpoint:           ${resumeInfo.checkpointHash}`,
		`Completed:            ${resumeInfo.completedAgents.length} agents (${resumeInfo.completedAgents.join(", ")})`,
		`================================================================================`,
		``,
	].join("\n");
}

/** Final summary block written when the workflow finishes (success or failure). */
export function buildCompletionBlock(
	summary: WorkflowSummary,
	workflowId: string | undefined,
	sessionMetadata: SessionMetadata,
): string {
	const status = summary.status === "completed" ? "COMPLETED" : "FAILED";

	const lines: string[] = [
		"",
		"================================================================================",
		`Workflow ${status}`,
		"────────────────────────────────────────",
		`Workflow ID: ${workflowId ?? sessionMetadata.id}`,
		`Status:      ${summary.status}`,
		`Duration:    ${formatDuration(summary.totalDurationMs)}`,
		`Agents:      ${summary.completedAgents.length} completed`,
	];

	if (summary.error) {
		lines.push(formatErrorBlock(summary.error).trimEnd());
	}

	lines.push("");
	lines.push("Agent Breakdown:");

	for (const agentName of summary.completedAgents) {
		const metrics = summary.agentMetrics[agentName];
		if (metrics) {
			lines.push(`  - ${agentName} (${formatDuration(metrics.durationMs)})`);
		} else {
			lines.push(`  - ${agentName}`);
		}
	}

	lines.push(
		"================================================================================",
	);

	return `${lines.join("\n")}\n`;
}
