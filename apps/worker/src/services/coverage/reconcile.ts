// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Authoritative bridge between the two ways agents are named in this codebase:
 *
 *   - `skillTracker` and the workflow key by **agentName** (`injection-vuln`,
 *     `recon`, …) — the `ALL_AGENTS` / `AgentName` union.
 *   - prompt loading and `RECOMMENDED` key by **promptTemplate** name
 *     (`vuln-injection`, `recon`, `pre-recon-code`, …).
 *
 * The single source of truth is `AGENTS[agentName].promptTemplate`. We invert
 * it ONCE at module load and assert the mapping is total and consistent, so any
 * future drift (a new agent, a renamed template, a stray `RECOMMENDED` key)
 * fails loudly at startup instead of silently zeroing out coverage.
 */

import { AGENTS } from "../../session-manager/agents/index.js";
import { ALL_AGENTS } from "../../types/agents.js";
import type { AgentName } from "../../types/agents.js";
import { RECOMMENDED } from "../prompt-manager/skill-recommendations.js";

/** agentName → promptTemplate (single source of truth: `AGENTS`). */
export function promptForAgent(agent: AgentName): string {
	return AGENTS[agent].promptTemplate;
}

/** promptTemplate → agentName, built once from `AGENTS`. */
const PROMPT_TO_AGENT: ReadonlyMap<string, AgentName> = (() => {
	const map = new Map<string, AgentName>();
	for (const agent of ALL_AGENTS) {
		const prompt = AGENTS[agent].promptTemplate;
		const existing = map.get(prompt);
		if (existing !== undefined) {
			throw new Error(
				`coverage/reconcile: promptTemplate "${prompt}" maps to both ` +
					`"${existing}" and "${agent}"; agentName↔promptName must be 1:1`,
			);
		}
		map.set(prompt, agent);
	}
	return map;
})();

/** Inverse of `promptForAgent`; `undefined` for an unknown template. */
export function agentForPrompt(promptName: string): AgentName | undefined {
	return PROMPT_TO_AGENT.get(promptName);
}

/**
 * Load-time reconciliation guard. Proves (a) every agent round-trips
 * agent → prompt → agent and (b) every `RECOMMENDED` key names a real agent's
 * template. Throwing here surfaces drift at process start, not mid-scan.
 */
function assertReconciliation(): void {
	for (const agent of ALL_AGENTS) {
		const roundTripped = agentForPrompt(promptForAgent(agent));
		if (roundTripped !== agent) {
			throw new Error(
				`coverage/reconcile: "${agent}" did not round-trip ` +
					`(got "${String(roundTripped)}")`,
			);
		}
	}
	for (const promptName of Object.keys(RECOMMENDED)) {
		if (agentForPrompt(promptName) === undefined) {
			throw new Error(
				`coverage/reconcile: RECOMMENDED key "${promptName}" maps to no ` +
					"agent; it must match an AGENTS[*].promptTemplate",
			);
		}
	}
}

assertReconciliation();
