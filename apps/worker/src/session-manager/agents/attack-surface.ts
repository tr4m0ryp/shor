// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const attackSurfaceAgent: AgentDefinition = {
	name: "attack-surface",
	displayName: "Attack-surface agent",
	prerequisites: ["report"],
	promptTemplate: "attack-surface",
	deliverableFilename: "attack_surface_scenarios.json",
	modelTier: "large",
};

/**
 * Validates the attack-surface synthesis deliverables — both the JSON (machine-readable
 * source of truth) and the Markdown rendering are required.
 */
export const attackSurfaceValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const jsonFile = path.join(sourceDir, "attack_surface_scenarios.json");
	const markdownFile = path.join(sourceDir, "attack_surface_scenarios.md");

	const [jsonExists, markdownExists] = await Promise.all([
		fs.pathExists(jsonFile),
		fs.pathExists(markdownFile),
	]);

	if (!jsonExists) {
		logger.error("Missing required deliverable: attack_surface_scenarios.json");
	}
	if (!markdownExists) {
		logger.error("Missing required deliverable: attack_surface_scenarios.md");
	}

	return jsonExists && markdownExists;
};
