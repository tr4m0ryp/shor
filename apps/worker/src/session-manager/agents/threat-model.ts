// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { fs, path } from "zx";

import { parseThreatModel } from "../../services/threat-model/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentDefinition, AgentValidator } from "../../types/index.js";

/**
 * Threat-model prerequisite: runs after recon, before the vuln pass, to frame the
 * highest-value hypotheses (trust boundaries, assets, abuse cases) the category
 * agents then pursue. It reads the recon + pre-recon deliverables and emits both
 * a human-readable `threat_model_deliverable.md` and the machine-readable
 * `threat_model.json` the context-assembler renders into `{{THREAT_MODEL}}`.
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
const MODEL_JSON = "threat_model.json";

/**
 * Validate the threat-model output: the human-readable deliverable MUST exist,
 * and the machine-readable `threat_model.json` MUST exist and parse into the
 * threat-model schema (a JSON object carrying a `threats` array). Parsing is
 * tolerant of field-level drift but rejects a non-object / threats-less file so
 * a broken model is caught here rather than silently degrading every downstream
 * prompt to "(none)". Returns false (not throw) so the agent's normal
 * retry/fail machinery handles it.
 */
export const threatModelValidator: AgentValidator = async (
	sourceDir: string,
	logger: ActivityLogger,
): Promise<boolean> => {
	const deliverable = path.join(sourceDir, DELIVERABLE);
	const modelJson = path.join(sourceDir, MODEL_JSON);

	let ok = true;

	if (!(await fs.pathExists(deliverable))) {
		logger.warn(`threat-model deliverable missing: ${DELIVERABLE}`);
		ok = false;
	}

	if (!(await fs.pathExists(modelJson))) {
		logger.warn(`threat-model machine-readable model missing: ${MODEL_JSON}`);
		ok = false;
	} else {
		try {
			const text = await fs.readFile(modelJson, "utf8");
			if (parseThreatModel(text) === null) {
				logger.warn(
					`threat-model ${MODEL_JSON} did not parse into the threat-model schema (need a JSON object with a "threats" array)`,
				);
				ok = false;
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			logger.warn(`threat-model ${MODEL_JSON} could not be read: ${message}`);
			ok = false;
		}
	}

	return ok;
};
