// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
	exploitationRetryAgents,
	exploitationRetryValidators,
	exploitationValidators,
} from "./exploitation.js";
import { preReconAgent, preReconValidator } from "./pre-recon.js";
import { reconAgent, reconValidator } from "./recon.js";
import { reportAgent, reportValidator } from "./reporting.js";
import { screenAgents, screenValidators } from "./screen.js";
import {
	vulnerabilityAgents,
	vulnerabilityValidators,
} from "./vulnerability.js";

/** Central registry of all agent definitions according to PRD. */
export const AGENTS: Readonly<Record<AgentName, AgentDefinition>> =
	Object.freeze({
		"pre-recon": preReconAgent,
		recon: reconAgent,
		...vulnerabilityAgents,
		...screenAgents,
		...exploitationAgents,
		...exploitationRetryAgents,
		report: reportAgent,
		"attack-surface": attackSurfaceAgent,
	});

/** Direct agent-to-validator mapping — simpler than pattern matching. */
export const AGENT_VALIDATORS: Record<AgentName, AgentValidator> =
	Object.freeze({
		"pre-recon": preReconValidator,
		recon: reconValidator,
		...vulnerabilityValidators,
		...screenValidators,
		...exploitationValidators,
		...exploitationRetryValidators,
		report: reportValidator,
		"attack-surface": attackSurfaceValidator,
	});
