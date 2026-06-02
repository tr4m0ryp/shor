// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { ExploitationDecision, VulnType } from "../../types/agents.js";
import { err, ok } from "../../types/result.js";
import { asyncPipe } from "../../utils/functional.js";
import type { PentestError } from "../error-handling.js";
import { determineExploitationDecision } from "./pipeline/decision.js";
import {
	checkFileExistence,
	validateExistenceRules,
} from "./pipeline/existence.js";
import { createPaths } from "./pipeline/paths.js";
import { validateQueueContent } from "./pipeline/queue-content.js";
import type { SafeValidationResult } from "./types.js";

// Main functional validation pipeline.
export async function validateQueueAndDeliverable(
	vulnType: VulnType,
	sourceDir: string,
): Promise<ExploitationDecision> {
	return asyncPipe<ExploitationDecision>(
		createPaths(vulnType, sourceDir),
		checkFileExistence,
		validateExistenceRules,
		validateQueueContent,
		determineExploitationDecision,
	);
}

/**
 * Safely validate queue and deliverable files.
 * Returns Result<ExploitationDecision, PentestError> for explicit error handling.
 */
export async function validateQueueSafe(
	vulnType: VulnType,
	sourceDir: string,
): Promise<SafeValidationResult> {
	try {
		const result = await validateQueueAndDeliverable(vulnType, sourceDir);
		return ok(result);
	} catch (error) {
		return err(error as PentestError);
	}
}
