// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { AgentName } from "../types/index.js";

/** Phase names used for metrics aggregation across the pipeline. */
export type PhaseName =
	| "pre-recon"
	| "recon"
	| "vulnerability-analysis"
	| "exploitation"
	| "reporting"
	| "attack-surface";

/** Maps each agent to its corresponding phase (single source of truth). */
export const AGENT_PHASE_MAP: Readonly<Record<AgentName, PhaseName>> =
	Object.freeze({
		"pre-recon": "pre-recon",
		recon: "recon",
		"injection-vuln": "vulnerability-analysis",
		"xss-vuln": "vulnerability-analysis",
		"auth-vuln": "vulnerability-analysis",
		"authz-vuln": "vulnerability-analysis",
		"ssrf-vuln": "vulnerability-analysis",
		"injection-exploit": "exploitation",
		"xss-exploit": "exploitation",
		"auth-exploit": "exploitation",
		"authz-exploit": "exploitation",
		"ssrf-exploit": "exploitation",
		report: "reporting",
		"attack-surface": "attack-surface",
	});
