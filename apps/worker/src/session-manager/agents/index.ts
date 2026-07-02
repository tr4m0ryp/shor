// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type {
	AgentDefinition,
	AgentName,
	AgentValidator,
} from "../../types/index.js";
import {
	attackSurfaceAgent,
	attackSurfaceValidator,
} from "./attack-surface.js";
import {
	exploitationAgents,
	exploitationValidators,
} from "./exploitation.js";
import { preReconAgent, preReconValidator } from "./pre-recon.js";
import { reconAgent, reconValidator } from "./recon.js";
import { reportAgent, reportValidator } from "./reporting.js";
import { screenAgents, screenValidators } from "./screen.js";
import { threatModelAgent, threatModelValidator } from "./threat-model.js";
import {
	vulnerabilityAgents,
	vulnerabilityValidators,
} from "./vulnerability.js";

/** Central registry of all agent definitions according to PRD. */
export const AGENTS: Readonly<Record<AgentName, AgentDefinition>> =
	Object.freeze({
		"pre-recon": preReconAgent,
		recon: reconAgent,
		"threat-model": threatModelAgent,
		...vulnerabilityAgents,
		...screenAgents,
		...exploitationAgents,
		report: reportAgent,
		"attack-surface": attackSurfaceAgent,
	});

/** Direct agent-to-validator mapping — simpler than pattern matching. */
export const AGENT_VALIDATORS: Record<AgentName, AgentValidator> =
	Object.freeze({
		"pre-recon": preReconValidator,
		recon: reconValidator,
		"threat-model": threatModelValidator,
		...vulnerabilityValidators,
		...screenValidators,
		...exploitationValidators,
		report: reportValidator,
		"attack-surface": attackSurfaceValidator,
	});
