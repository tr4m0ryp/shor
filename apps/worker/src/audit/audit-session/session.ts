// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Audit Session - Main Facade
 *
 * Coordinates logger, metrics tracker, and concurrency control for comprehensive
 * crash-safe audit logging.
 */

import { PentestError } from "../../services/error-handling.js";
import { ErrorCode } from "../../types/errors.js";
import type { AgentEndResult } from "../../types/index.js";
import { formatTimestamp } from "../../utils/formatting.js";
import { AgentLogger } from "../logger.js";
import { MetricsTracker } from "../metrics-tracker.js";
import { initializeAuditStructure, type SessionMetadata } from "../utils.js";
import {
	type AgentLogDetails,
	WorkflowLogger,
	type WorkflowSummary,
} from "../workflow-logger.js";
import { routeEventToWorkflowLog } from "./event-router.js";
import { sessionMutex } from "./mutex.js";
import { validateSessionMetadata } from "./validation.js";

/**
 * AuditSession - Main audit system facade
 */
export class AuditSession {
	private sessionMetadata: SessionMetadata;
	private sessionId: string;
	private metricsTracker: MetricsTracker;
	private workflowLogger: WorkflowLogger;
	private currentLogger: AgentLogger | null = null;
	private currentAgentName: string | null = null;
	private initialized: boolean = false;

	constructor(sessionMetadata: SessionMetadata) {
		validateSessionMetadata(sessionMetadata);

		this.sessionMetadata = sessionMetadata;
		this.sessionId = sessionMetadata.id;

		// Components
		this.metricsTracker = new MetricsTracker(sessionMetadata);
		this.workflowLogger = new WorkflowLogger(sessionMetadata);
	}

	/**
	 * Initialize audit session (creates directories, session.json)
	 * Idempotent and race-safe
	 *
	 * @param workflowId - Optional workflow ID for tracking original or resume workflows
	 */
	async initialize(workflowId?: string): Promise<void> {
		if (this.initialized) {
			return; // Already initialized
		}

		// Create directory structure
		await initializeAuditStructure(this.sessionMetadata);

		// Initialize metrics tracker (loads or creates session.json)
		await this.metricsTracker.initialize(workflowId);

		// Initialize workflow logger with actual Temporal workflow ID
		await this.workflowLogger.initialize(workflowId);

		this.initialized = true;
	}

	/**
	 * Ensure initialized (helper for lazy initialization)
	 */
	private async ensureInitialized(): Promise<void> {
		if (!this.initialized) {
			await this.initialize();
		}
	}

	/**
	 * Start agent execution
	 */
	async startAgent(
		agentName: string,
		promptContent: string,
		attemptNumber: number = 1,
	): Promise<void> {
		await this.ensureInitialized();

		// 1. Save prompt snapshot (only on first attempt)
		if (attemptNumber === 1) {
			await AgentLogger.savePrompt(
				this.sessionMetadata,
				agentName,
				promptContent,
			);
		}

		// 2. Create and initialize the per-agent logger
		this.currentAgentName = agentName;
		this.currentLogger = new AgentLogger(
			this.sessionMetadata,
			agentName,
			attemptNumber,
		);
		await this.currentLogger.initialize();

		// 3. Start metrics timer
		this.metricsTracker.startAgent(agentName, attemptNumber);

		// 4. Log start event to both agent log and workflow log
		await this.currentLogger.logEvent("agent_start", {
			agentName,
			attemptNumber,
			timestamp: formatTimestamp(),
		});

		await this.workflowLogger.logAgent(agentName, "start", { attemptNumber });
	}

	/**
	 * Log event during agent execution
	 */
	async logEvent(eventType: string, eventData: unknown): Promise<void> {
		if (!this.currentLogger) {
			throw new PentestError(
				"No active logger. Call startAgent() first.",
				"validation",
				false,
				{},
				ErrorCode.AGENT_EXECUTION_FAILED,
			);
		}

		// Log to agent-specific log file (JSON format)
		await this.currentLogger.logEvent(eventType, eventData);

		// Also log to unified workflow log (human-readable format)
		const agentName = this.currentAgentName || "unknown";
		await routeEventToWorkflowLog(
			this.workflowLogger,
			agentName,
			eventType,
			eventData,
		);
	}

	/**
	 * End agent execution (mutex-protected)
	 */
	async endAgent(agentName: string, result: AgentEndResult): Promise<void> {
		// 1. Finalize agent log and close the stream
		if (this.currentLogger) {
			await this.currentLogger.logEvent("agent_end", {
				agentName,
				success: result.success,
				duration_ms: result.duration_ms,
				timestamp: formatTimestamp(),
			});

			await this.currentLogger.close();
			this.currentLogger = null;
		}

		// 2. Log completion to the unified workflow log
		this.currentAgentName = null;

		const agentLogDetails: AgentLogDetails = {
			attemptNumber: result.attemptNumber,
			duration_ms: result.duration_ms,
			success: result.success,
			...(result.error !== undefined && { error: result.error }),
		};
		await this.workflowLogger.logAgent(agentName, "end", agentLogDetails);

		// 3. Acquire mutex before touching session.json
		const unlock = await sessionMutex.lock(this.sessionId);
		try {
			// 4. Reload-then-write inside mutex to prevent lost updates during parallel phases
			await this.metricsTracker.reload();
			await this.metricsTracker.endAgent(agentName, result);
		} finally {
			unlock();
		}
	}

	/**
	 * Update session status
	 */
	async updateSessionStatus(
		status: "in-progress" | "completed" | "failed" | "cancelled",
	): Promise<void> {
		await this.ensureInitialized();

		const unlock = await sessionMutex.lock(this.sessionId);
		try {
			await this.metricsTracker.reload();
			await this.metricsTracker.updateSessionStatus(status);
		} finally {
			unlock();
		}
	}

	/**
	 * Get current metrics (read-only)
	 */
	async getMetrics(): Promise<unknown> {
		await this.ensureInitialized();
		return this.metricsTracker.getMetrics();
	}

	/**
	 * Log phase start to unified workflow log
	 */
	async logPhaseStart(phase: string): Promise<void> {
		await this.ensureInitialized();
		await this.workflowLogger.logPhase(phase, "start");
	}

	/**
	 * Log phase completion to unified workflow log
	 */
	async logPhaseComplete(phase: string): Promise<void> {
		await this.ensureInitialized();
		await this.workflowLogger.logPhase(phase, "complete");
	}

	/**
	 * Log workflow completion to unified workflow log
	 */
	async logWorkflowComplete(summary: WorkflowSummary): Promise<void> {
		await this.ensureInitialized();
		await this.workflowLogger.logWorkflowComplete(summary);
	}

	/**
	 * Add a resume attempt to the session
	 * Call this when a workflow is resuming from an existing workspace
	 *
	 * @param workflowId - The new workflow ID for this resume attempt
	 * @param terminatedWorkflows - IDs of workflows that were terminated
	 * @param checkpointHash - Git checkpoint hash that was restored
	 */
	async addResumeAttempt(
		workflowId: string,
		terminatedWorkflows: string[],
		checkpointHash?: string,
	): Promise<void> {
		await this.ensureInitialized();

		const unlock = await sessionMutex.lock(this.sessionId);
		try {
			await this.metricsTracker.reload();
			await this.metricsTracker.addResumeAttempt(
				workflowId,
				terminatedWorkflows,
				checkpointHash,
			);
		} finally {
			unlock();
		}
	}

	/**
	 * Log resume header to workflow.log
	 * Call this when a workflow is resuming to add a visual separator
	 */
	async logResumeHeader(resumeInfo: {
		previousWorkflowId: string;
		newWorkflowId: string;
		checkpointHash: string;
		completedAgents: string[];
	}): Promise<void> {
		await this.ensureInitialized();
		await this.workflowLogger.logResumeHeader(resumeInfo);
	}
}
