// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Threat-model service (spec decision T1).
 *
 * Public surface:
 *   - {@link parseThreatModel} / {@link ThreatModel} types — read + validate the
 *     agent-emitted `threat_model.json` (used by the agent validator and, for
 *     finding -> threat mapping, by downstream severity in task 015).
 *   - {@link renderThreatModel} — the compact `{{THREAT_MODEL}}` summary.
 *   - {@link assembleScanPromptContext} — build the per-scan PromptContext that
 *     injects the threat model (and sibling artifacts) into agent prompts.
 */

export {
	assembleScanPromptContext,
	FP_RULES_ENV,
	HISTORICAL_SIGNAL_FILE,
	SCAN_IDENTITIES_FILE,
	THREAT_MODEL_FILE,
} from "./assemble.js";
export { renderHistoricalSeed, renderIdentities } from "./artifacts.js";
export { renderThreatModel } from "./render.js";
export {
	type Asset,
	type Deprioritized,
	type EntryPoint,
	IMPACT_LEVELS,
	type ImpactLevel,
	impactOrdinal,
	LIKELIHOOD_LEVELS,
	type LikelihoodLevel,
	likelihoodOrdinal,
	parseThreatModel,
	type Provenance,
	SENSITIVITY_LEVELS,
	type SensitivityLevel,
	sensitivityOrdinal,
	type Threat,
	type ThreatActor,
	THREAT_ACTORS,
	type ThreatModel,
	threatScore,
} from "./schema.js";
