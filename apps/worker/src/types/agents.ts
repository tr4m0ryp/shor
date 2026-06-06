// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Agent type definitions
 */

/**
 * List of all agents in execution order.
 * Used for iteration during resume state checking.
 */
export const ALL_AGENTS = [
	"pre-recon",
	"recon",
	// Threat-model prerequisite: runs after recon, before the vuln pass, to frame
	// the highest-value hypotheses for the category agents.
	"threat-model",
	"injection-vuln",
	"xss-vuln",
	"auth-vuln",
	"ssrf-vuln",
	"authz-vuln",
	// +2 categories (logic flaws, web misconfiguration) run alongside the existing
	// five in every phase.
	"logic-vuln",
	"misconfig-web-vuln",
	// Adversarial screen pass: one agent per category independently tries to
	// refute each hypothesis (blind to recon context) before exploitation.
	"injection-screen",
	"xss-screen",
	"auth-screen",
	"ssrf-screen",
	"authz-screen",
	"logic-screen",
	"misconfig-web-screen",
	"injection-exploit",
	"xss-exploit",
	"auth-exploit",
	"ssrf-exploit",
	"authz-exploit",
	"logic-exploit",
	"misconfig-web-exploit",
	"report",
	"attack-surface",
] as const;

/**
 * Agent name type derived from ALL_AGENTS.
 * This ensures type safety and prevents drift between type and array.
 */
export type AgentName = (typeof ALL_AGENTS)[number];

export type PlaywrightSession =
	| "agent1"
	| "agent2"
	| "agent3"
	| "agent4"
	| "agent5"
	| "agent6"
	| "agent7";

import type { ActivityLogger } from "./activity-logger.js";

export type AgentValidator = (
	sourceDir: string,
	logger: ActivityLogger,
) => Promise<boolean>;

export type AgentStatus =
	| "pending"
	| "in_progress"
	| "completed"
	| "failed"
	| "rolled-back";

export interface AgentDefinition {
	name: AgentName;
	displayName: string;
	prerequisites: AgentName[];
	promptTemplate: string;
	deliverableFilename: string;
	modelTier?: "small" | "medium" | "large";
}

/**
 * Vulnerability types supported by the pipeline.
 */
export type VulnType = "injection" | "xss" | "auth" | "ssrf" | "authz";

/**
 * Decision returned by queue validation for exploitation phase.
 */
export interface ExploitationDecision {
	shouldExploit: boolean;
	shouldRetry: boolean;
	vulnerabilityCount: number;
	vulnType: VulnType;
}
