// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

export const preReconAgent: AgentDefinition = {
	name: "pre-recon",
	displayName: "Pre-recon agent",
	prerequisites: [],
	promptTemplate: "pre-recon-code",
	deliverableFilename: "pre_recon_deliverable.md",
	modelTier: "large",
};

const DELIVERABLE = "pre_recon_deliverable.md";

/**
 * Validate the pre-recon code-analysis deliverable, degrading gracefully when it
 * is absent.
 *
 * Pre-recon is a SOURCE-CODE agent. On a black-box scan (no repository) — or a
 * repo with no analyzable source — it has nothing to analyze, and the flash model
 * sometimes writes a `coverage_check.md` summary instead of the required
 * deliverable. Hard-failing here aborts the ENTIRE scan at agent 1/14, even
 * though the downstream live-target (DAST) agents could run fine. So, mirroring
 * the vuln-agents' `ensureQueueFile` pattern, synthesize a minimal deliverable
 * (seeded from whatever the agent did produce) and pass, instead of crashing.
 */
export const preReconValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const deliverable = path.join(sourceDir, DELIVERABLE);
	if (await fs.pathExists(deliverable)) return true;

	const coverage = path.join(sourceDir, "coverage_check.md");
	const notes = (await fs.pathExists(coverage)) ? await fs.readFile(coverage, "utf8") : "";
	const synthesized =
		`# Pre-recon Code Analysis\n\n` +
		`No source-code deliverable was produced. This is a black-box scan (no ` +
		`repository was provided) or the repository contained no analyzable source. ` +
		`Proceeding with live-target reconnaissance; downstream agents operate ` +
		`against the running application.\n\n` +
		(notes ? `## Coverage notes\n\n${notes}\n` : "");
	await fs.writeFile(deliverable, synthesized);
	logger.warn(
		"pre-recon deliverable missing (black-box / no source); synthesized a placeholder so the scan continues",
	);
	return true;
};
