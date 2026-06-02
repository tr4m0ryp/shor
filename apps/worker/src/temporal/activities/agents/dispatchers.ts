// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-agent activity entry points.
 *
 * Thin wrappers around `runAgentActivity` that bind each AgentName to a
 * Temporal-discoverable function. Attack-surface honours the
 * `STORRON_DISABLE_ATTACK_SURFACE=1` escape hatch.
 */

import { createActivityLogger } from "../../activity-logger.js";
import type { AgentMetrics } from "../../shared.js";
import type { ActivityInput } from "../types.js";
import { runAgentActivity } from "./execute.js";

export async function runPreReconAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("pre-recon", input);
}

export async function runReconAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("recon", input);
}

export async function runInjectionVulnAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("injection-vuln", input);
}

export async function runXssVulnAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("xss-vuln", input);
}

export async function runAuthVulnAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("auth-vuln", input);
}

export async function runSsrfVulnAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("ssrf-vuln", input);
}

export async function runAuthzVulnAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("authz-vuln", input);
}

export async function runInjectionExploitAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("injection-exploit", input);
}

export async function runXssExploitAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("xss-exploit", input);
}

export async function runAuthExploitAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("auth-exploit", input);
}

export async function runSsrfExploitAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("ssrf-exploit", input);
}

export async function runAuthzExploitAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("authz-exploit", input);
}

export async function runReportAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	return runAgentActivity("report", input);
}

/**
 * Attack-surface synthesis activity.
 *
 * Respects the `STORRON_DISABLE_ATTACK_SURFACE=1` env var as an operator
 * escape hatch. When disabled, returns zeroed metrics so the workflow
 * records the phase as a no-op rather than a failure.
 *
 * Output-validation errors share the report agent's policy: not worth
 * retrying blindly because synthesis is expensive. Transient infra errors
 * are still retried by `runAgentActivity`.
 */
export async function runAttackSurfaceAgent(
	input: ActivityInput,
): Promise<AgentMetrics> {
	if (process.env.STORRON_DISABLE_ATTACK_SURFACE === "1") {
		const logger = createActivityLogger();
		logger.info(
			"Attack-surface phase skipped via STORRON_DISABLE_ATTACK_SURFACE=1",
		);
		return {
			durationMs: 0,
			inputTokens: null,
			outputTokens: null,
			numTurns: null,
			model: "skipped",
		};
	}
	return runAgentActivity("attack-surface", input);
}
