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
	| "threat-model"
	| "vulnerability-analysis"
	| "adversarial-screen"
	| "exploitation"
	| "oracle"
	| "reporting"
	| "attack-surface";

/** Maps each agent to its corresponding phase (single source of truth). */
export const AGENT_PHASE_MAP: Readonly<Record<AgentName, PhaseName>> =
	Object.freeze({
		"pre-recon": "pre-recon",
		recon: "recon",
		"threat-model": "threat-model",
		"injection-vuln": "vulnerability-analysis",
		"xss-vuln": "vulnerability-analysis",
		"auth-vuln": "vulnerability-analysis",
		"authz-vuln": "vulnerability-analysis",
		"ssrf-vuln": "vulnerability-analysis",
		"logic-vuln": "vulnerability-analysis",
		"misconfig-web-vuln": "vulnerability-analysis",
		"injection-screen": "adversarial-screen",
		"xss-screen": "adversarial-screen",
		"auth-screen": "adversarial-screen",
		"authz-screen": "adversarial-screen",
		"ssrf-screen": "adversarial-screen",
		"logic-screen": "adversarial-screen",
		"misconfig-web-screen": "adversarial-screen",
		"injection-exploit": "exploitation",
		"xss-exploit": "exploitation",
		"auth-exploit": "exploitation",
		"authz-exploit": "exploitation",
		"ssrf-exploit": "exploitation",
		"logic-exploit": "exploitation",
		"misconfig-web-exploit": "exploitation",
		report: "reporting",
		"attack-surface": "attack-surface",
	});
