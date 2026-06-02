// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { skillTracker } from "../../job/progress/skill-tracker.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AuditLogger } from "../audit-logger.js";
import {
	formatAssistantOutput,
	formatResultOutput,
	formatToolResultOutput,
	formatToolUseOutput,
} from "../output-formatters.js";
import type { ProgressManager } from "../progress-manager.js";
import { getActualModelName } from "../router-utils.js";
import type {
	AssistantMessage,
	ExecutionContext,
	ResultMessage,
	SystemInitMessage,
	ToolResultMessage,
	ToolUseMessage,
} from "../types.js";
import { handleAssistantMessage } from "./handlers/assistant.js";
import { handleResultMessage } from "./handlers/result.js";
import { handleToolResultMessage } from "./handlers/tool-result.js";
import { handleToolUseMessage } from "./handlers/tool-use.js";

function outputLines(lines: string[]): void {
	for (const line of lines) {
		console.log(line);
	}
}

export type MessageDispatchAction =
	| {
			type: "continue";
			apiErrorDetected?: boolean | undefined;
			model?: string | undefined;
	  }
	| {
			type: "complete";
			result: string | null;
			inputTokens?: number;
			outputTokens?: number;
			cacheReadInputTokens?: number;
			cacheCreationInputTokens?: number;
			numTurns?: number;
			structuredOutput?: unknown;
	  }
	| { type: "throw"; error: Error };

export interface MessageDispatchDeps {
	execContext: ExecutionContext;
	description: string;
	progress: ProgressManager;
	auditLogger: AuditLogger;
	logger: ActivityLogger;
}

// Dispatches SDK messages to appropriate handlers and formatters
export async function dispatchMessage(
	message: { type: string; subtype?: string },
	turnCount: number,
	deps: MessageDispatchDeps,
): Promise<MessageDispatchAction> {
	const { execContext, description, progress, auditLogger, logger } = deps;

	switch (message.type) {
		case "assistant": {
			// The current SDK nests tool_use inside assistant content rather than
			// emitting a top-level "tool_use" message, so the case below never
			// fires. Capture tool calls HERE for the live skills feed.
			const am = message as AssistantMessage;
			if (Array.isArray(am.message?.content)) {
				for (const block of am.message.content) {
					const tb = block as { type?: string; name?: string; input?: Record<string, unknown> };
					if (tb.type === "tool_use" && typeof tb.name === "string") {
						skillTracker.record(tb.name, tb.input ?? {});
					}
				}
			}

			const assistantResult = handleAssistantMessage(
				message as AssistantMessage,
				turnCount,
			);

			if (assistantResult.shouldThrow) {
				return { type: "throw", error: assistantResult.shouldThrow };
			}

			if (assistantResult.cleanedContent.trim()) {
				progress.stop();
				outputLines(
					formatAssistantOutput(
						assistantResult.cleanedContent,
						execContext,
						turnCount,
						description,
					),
				);
				progress.start();
			}

			await auditLogger.logLlmResponse(turnCount, assistantResult.content);

			if (assistantResult.apiErrorDetected) {
				logger.warn("API Error detected in assistant response");
				return { type: "continue", apiErrorDetected: true };
			}

			return { type: "continue" };
		}

		case "system": {
			if (message.subtype === "init") {
				const initMsg = message as SystemInitMessage;
				const actualModel = getActualModelName(initMsg.model);
				if (!execContext.useCleanOutput) {
					logger.info(
						`Model: ${actualModel}, Permission: ${initMsg.permissionMode}`,
					);
				}
				// Return actual model for tracking in audit logs
				return { type: "continue", model: actualModel };
			}
			return { type: "continue" };
		}

		case "user":
		case "tool_progress":
		case "tool_use_summary":
		case "auth_status":
			return { type: "continue" };

		case "tool_use": {
			const toolData = handleToolUseMessage(
				message as unknown as ToolUseMessage,
			);
			// Attribute the tool call to the running agent for the live skills feed.
			skillTracker.record(toolData.toolName, toolData.parameters);
			outputLines(formatToolUseOutput(toolData.toolName, toolData.parameters));
			await auditLogger.logToolStart(toolData.toolName, toolData.parameters);
			return { type: "continue" };
		}

		case "tool_result": {
			const toolResultData = handleToolResultMessage(
				message as unknown as ToolResultMessage,
			);
			outputLines(formatToolResultOutput(toolResultData.displayContent));
			await auditLogger.logToolEnd(toolResultData.content);
			return { type: "continue" };
		}

		case "result": {
			const resultData = handleResultMessage(message as ResultMessage);
			outputLines(formatResultOutput(resultData, !execContext.useCleanOutput));

			if (resultData.subtype === "error_max_structured_output_retries") {
				// Non-fatal: structured output is disabled in all-flash mode, but if
				// it is ever re-enabled and the model exhausts retries, don't crash —
				// complete with whatever text we have. The queue backstop
				// (ensureQueueFile) guarantees a valid queue file downstream.
				logger.warn(
					"Structured output retries exhausted; continuing (queue backstop applies)",
				);
				return { type: "complete" as const, result: resultData.result };
			}

			return {
				type: "complete" as const,
				result: resultData.result,
				...(resultData.inputTokens !== undefined && {
					inputTokens: resultData.inputTokens,
				}),
				...(resultData.outputTokens !== undefined && {
					outputTokens: resultData.outputTokens,
				}),
				...(resultData.cacheReadInputTokens !== undefined && {
					cacheReadInputTokens: resultData.cacheReadInputTokens,
				}),
				...(resultData.cacheCreationInputTokens !== undefined && {
					cacheCreationInputTokens: resultData.cacheCreationInputTokens,
				}),
				...(resultData.numTurns !== undefined && {
					numTurns: resultData.numTurns,
				}),
				...(resultData.structuredOutput !== undefined && {
					structuredOutput: resultData.structuredOutput,
				}),
			};
		}

		default:
			logger.info(`Unhandled message type: ${message.type}`);
			return { type: "continue" };
	}
}
