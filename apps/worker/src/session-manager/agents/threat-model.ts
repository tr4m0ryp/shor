// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

/**
 * Threat-model prerequisite: runs after recon, before the vuln pass, to frame the
 * highest-value hypotheses (trust boundaries, assets, abuse cases) the category
 * agents then pursue. STUB skeleton — task 009 fills the real prompt + validation.
 */
export const threatModelAgent: AgentDefinition = {
	name: "threat-model",
	displayName: "Threat-model agent",
	prerequisites: ["recon"],
	promptTemplate: "threat-model",
	deliverableFilename: "threat_model_deliverable.md",
	modelTier: "large",
};

const DELIVERABLE = "threat_model_deliverable.md";

/**
 * Validate the threat-model deliverable. Skeleton: threat-model runs in the
 * fail-fast prerequisite sequence and its prompt is still a stub (task 009),
 * so this MUST NOT hard-fail the scan. It passes unconditionally, warning when
 * the deliverable is absent so the gap stays visible in the run logs. Task 009
 * replaces this with a real check.
 */
export const threatModelValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const deliverable = path.join(sourceDir, DELIVERABLE);
	if (!(await fs.pathExists(deliverable))) {
		logger.warn(
			"threat-model deliverable missing (stub phase); continuing without blocking the scan",
		);
	}
	return true;
};
