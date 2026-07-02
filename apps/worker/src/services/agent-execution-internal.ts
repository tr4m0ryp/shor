// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Internal helpers for AgentExecutionService.
 *
 * Split out of `agent-execution.ts` to keep the service file under the
 * 300-line cap. Not exported through the package barrel - consumers should
 * use `AgentExecutionService` from `./agent-execution.js`.
 */

import type { ClaudePromptResult } from "../ai/claude-executor.js";
import type { AuditSession } from "../audit/index.js";
import type { ActivityLogger } from "../types/activity-logger.js";
import type { AgentName } from "../types/agents.js";
import type { AgentEndResult } from "../types/audit.js";
import type { ErrorCode, PentestErrorType } from "../types/errors.js";
import { err, type Result } from "../types/result.js";
import { PentestError } from "./error-handling.js";
import { rollbackGitWorkspace } from "./git-manager.js";

/** Options passed to `failAgent` describing how to record and surface a failure. */
export interface FailAgentOpts {
	attemptNumber: number;
	result: ClaudePromptResult;
	rollbackReason: string;
	errorMessage: string;
	errorCode: ErrorCode;
	category: PentestErrorType;
	retryable: boolean;
	context: Record<string, unknown>;
}

/**
 * Roll back the git workspace, write the failure end-result to the audit log,
 * and return the wrapped `PentestError` for the caller to propagate.
 */
export async function failAgent(
	agentName: AgentName,
	deliverablesPath: string,
	auditSession: AuditSession,
	logger: ActivityLogger,
	opts: FailAgentOpts,
): Promise<Result<AgentEndResult, PentestError>> {
	await rollbackGitWorkspace(deliverablesPath, opts.rollbackReason, logger);

	const endResult: AgentEndResult = {
		attemptNumber: opts.attemptNumber,
		duration_ms: opts.result.duration,
		success: false,
		model: opts.result.model,
		error: opts.errorMessage,
		...(opts.result.inputTokens !== undefined && {
			input_tokens: opts.result.inputTokens,
		}),
		...(opts.result.outputTokens !== undefined && {
			output_tokens: opts.result.outputTokens,
		}),
		...(opts.result.cacheReadInputTokens !== undefined && {
			cache_read_input_tokens: opts.result.cacheReadInputTokens,
		}),
		...(opts.result.cacheCreationInputTokens !== undefined && {
			cache_creation_input_tokens: opts.result.cacheCreationInputTokens,
		}),
		...(opts.result.turns !== undefined && { num_turns: opts.result.turns }),
	};
	await auditSession.endAgent(agentName, endResult);

	return err(
		new PentestError(
			opts.errorMessage,
			opts.category,
			opts.retryable,
			opts.context,
			opts.errorCode,
		),
	);
}
