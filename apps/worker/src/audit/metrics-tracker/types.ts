// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

export interface AttemptData {
	attempt_number: number;
	duration_ms: number;
	success: boolean;
	timestamp: string;
	model?: string | undefined;
	error?: string | undefined;
}

export interface AgentAuditMetrics {
	status: "in-progress" | "success" | "failed";
	attempts: AttemptData[];
	final_duration_ms: number;
	model?: string | undefined;
	checkpoint?: string | undefined;
}

export interface PhaseMetrics {
	duration_ms: number;
	duration_percentage: number;
	agent_count: number;
}

export interface ResumeAttempt {
	workflowId: string;
	timestamp: string;
	terminatedPrevious?: string;
	resumedFromCheckpoint?: string;
}

export interface SessionData {
	session: {
		id: string;
		webUrl: string;
		repoPath?: string;
		status: "in-progress" | "completed" | "failed" | "cancelled";
		createdAt: string;
		completedAt?: string;
		originalWorkflowId?: string; // First workflow that created this workspace
		resumeAttempts?: ResumeAttempt[]; // Track all resume attempts
	};
	metrics: {
		total_duration_ms: number;
		phases: Record<string, PhaseMetrics>;
		agents: Record<string, AgentAuditMetrics>;
	};
}

export interface ActiveTimer {
	startTime: number;
	attemptNumber: number;
}
