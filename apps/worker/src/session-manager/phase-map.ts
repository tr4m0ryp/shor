// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
