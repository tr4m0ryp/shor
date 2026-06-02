// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Exploitation-queue activities.
 *
 * Read the queue gate before launching exploits and merge externally
 * supplied findings into the queue when a FindingsProvider is configured.
 */

import { deliverablesDir } from "../../paths.js";
import { getContainer } from "../../services/container.js";
import { ExploitationCheckerService } from "../../services/exploitation-checker.js";
import type {
	ExploitationDecision,
	VulnType,
} from "../../services/queue-validation.js";
import { createActivityLogger } from "../activity-logger.js";
import type { ActivityInput } from "./types.js";

/**
 * Check if exploitation should run for a given vulnerability type.
 *
 * Uses existing container if available (from prior agent runs),
 * otherwise creates service directly (stateless, no dependencies).
 */
export async function checkExploitationQueue(
	input: ActivityInput,
	vulnType: VulnType,
): Promise<ExploitationDecision> {
	const { repoPath, workflowId } = input;
	const logger = createActivityLogger();

	// Reuse container's service if available (from prior vuln agent runs)
	const existingContainer = getContainer(workflowId);
	const checker =
		existingContainer?.exploitationChecker ?? new ExploitationCheckerService();

	// Pass deliverablesPath (not repoPath) — validators expect the deliverables directory
	const delivPath = deliverablesDir(repoPath, input.deliverablesSubdir);
	return checker.checkQueue(vulnType, delivPath, logger);
}

/**
 * Merge external findings into the exploitation queue for a vulnerability type.
 *
 * Delegates to the FindingsProvider registered in the DI container.
 * Default: no-op returning { mergedCount: 0 }.
 * Consumers can override this activity at the worker level with custom findings integration.
 */
export async function mergeFindingsIntoQueue(
	input: ActivityInput,
	vulnType: VulnType,
): Promise<{ mergedCount: number }> {
	const container = getContainer(input.workflowId);
	if (!container?.findingsProvider) return { mergedCount: 0 };
	return container.findingsProvider.mergeFindingsIntoQueue(
		input.repoPath,
		vulnType,
		input,
	);
}
