// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const reconAgent: AgentDefinition = {
	name: "recon",
	displayName: "Recon agent",
	prerequisites: ["pre-recon"],
	promptTemplate: "recon",
	deliverableFilename: "recon_deliverable.md",
};

/** Validates the recon deliverable. */
export const reconValidator: AgentValidator = async (
	sourceDir: string,
): Promise<boolean> => {
	const reconFile = path.join(sourceDir, "recon_deliverable.md");
	return await fs.pathExists(reconFile);
};
