// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const reportAgent: AgentDefinition = {
	name: "report",
	displayName: "Report agent",
	prerequisites: [
		"injection-exploit",
		"xss-exploit",
		"auth-exploit",
		"ssrf-exploit",
		"authz-exploit",
	],
	promptTemplate: "report-executive",
	deliverableFilename: "comprehensive_security_assessment_report.md",
	modelTier: "small",
};

/** Validates the executive report deliverable. */
export const reportValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const reportFile = path.join(
		sourceDir,
		"comprehensive_security_assessment_report.md",
	);

	const reportExists = await fs.pathExists(reportFile);

	if (!reportExists) {
		logger.error(
			"Missing required deliverable: comprehensive_security_assessment_report.md",
		);
	}

	return reportExists;
};
