// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { AGENT_VALIDATORS } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { ClaudePromptResult } from "./types.js";

/**
 * Validate that an agent's run produced the deliverables required by its registered validator.
 * Returns true when the agent succeeded and (optionally) any registered validator passes.
 */
export async function validateAgentOutput(
	result: ClaudePromptResult,
	agentName: string | null,
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> {
	logger.info(`Validating ${agentName} agent output`);

	try {
		// Check if agent completed successfully (text result OR structured output)
		if (
			!result.success ||
			(!result.result && result.structuredOutput === undefined)
		) {
			logger.error("Validation failed: Agent execution was unsuccessful");
			return false;
		}

		// Get validator function for this agent
		const validator = agentName
			? AGENT_VALIDATORS[agentName as keyof typeof AGENT_VALIDATORS]
			: undefined;

		if (!validator) {
			logger.warn(
				`No validator found for agent "${agentName}" - assuming success`,
			);
			logger.info("Validation passed: Unknown agent with successful result");
			return true;
		}

		logger.info(`Using validator for agent: ${agentName}`, { sourceDir });

		// Apply validation function
		const validationResult = await validator(sourceDir, logger);

		if (validationResult) {
			logger.info("Validation passed: Required files/structure present");
		} else {
			logger.error("Validation failed: Missing required deliverable files");
		}

		return validationResult;
	} catch (error) {
		const errMsg = error instanceof Error ? error.message : String(error);
		logger.error(`Validation failed with error: ${errMsg}`);
		return false;
	}
}
