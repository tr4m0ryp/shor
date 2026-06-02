// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const preReconAgent: AgentDefinition = {
	name: "pre-recon",
	displayName: "Pre-recon agent",
	prerequisites: [],
	promptTemplate: "pre-recon-code",
	deliverableFilename: "pre_recon_deliverable.md",
	modelTier: "large",
};

/** Validates the code analysis deliverable produced by the pre-recon agent. */
export const preReconValidator: AgentValidator = async (
	sourceDir: string,
): Promise<boolean> => {
	const codeAnalysisFile = path.join(sourceDir, "pre_recon_deliverable.md");
	return await fs.pathExists(codeAnalysisFile);
};
