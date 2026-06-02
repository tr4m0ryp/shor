// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
