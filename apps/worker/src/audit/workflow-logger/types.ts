// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

export interface AgentLogDetails {
	attemptNumber?: number;
	duration_ms?: number;
	success?: boolean;
	error?: string;
}

export interface AgentMetricsSummary {
	durationMs: number;
}

export interface WorkflowSummary {
	status: "completed" | "failed" | "cancelled";
	totalDurationMs: number;
	completedAgents: string[];
	agentMetrics: Record<string, AgentMetricsSummary>;
	error?: string;
}
