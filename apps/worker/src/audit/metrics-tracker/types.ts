// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
