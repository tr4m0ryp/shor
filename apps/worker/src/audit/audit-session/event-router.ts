// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { WorkflowLogger } from "../workflow-logger/index.js";

/**
 * Route a per-agent event into the unified human-readable workflow log.
 *
 * Only a subset of event types are forwarded; `tool_end` and `error` events
 * are intentionally omitted because the agent completion message already
 * captures the outcome.
 */
export async function routeEventToWorkflowLog(
	workflowLogger: WorkflowLogger,
	agentName: string,
	eventType: string,
	eventData: unknown,
): Promise<void> {
	const data = eventData as Record<string, unknown>;

	switch (eventType) {
		case "tool_start":
			await workflowLogger.logToolStart(
				agentName,
				String(data.toolName || ""),
				data.parameters,
			);
			break;
		case "llm_response":
			await workflowLogger.logLlmResponse(
				agentName,
				Number(data.turn || 0),
				String(data.content || ""),
			);
			break;
		// tool_end and error events are intentionally not logged to workflow log
		// to reduce noise - the agent completion message captures the outcome
	}
}
