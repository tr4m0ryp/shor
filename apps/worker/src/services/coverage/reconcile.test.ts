// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { AGENTS } from "../../session-manager/agents/index.js";
import { ALL_AGENTS } from "../../types/agents.js";
import { RECOMMENDED } from "../prompt-manager/skill-recommendations.js";
import { agentForPrompt, promptForAgent } from "./reconcile.js";

describe("reconcile", () => {
	it("promptForAgent returns the AGENTS promptTemplate", () => {
		for (const agent of ALL_AGENTS) {
			expect(promptForAgent(agent)).toBe(AGENTS[agent].promptTemplate);
		}
	});

	it("every agent round-trips agent -> prompt -> agent", () => {
		for (const agent of ALL_AGENTS) {
			expect(agentForPrompt(promptForAgent(agent))).toBe(agent);
		}
	});

	it("agentForPrompt returns undefined for an unknown template", () => {
		expect(agentForPrompt("does-not-exist")).toBeUndefined();
		expect(agentForPrompt("")).toBeUndefined();
	});

	it("every RECOMMENDED key maps to a real agent", () => {
		for (const promptName of Object.keys(RECOMMENDED)) {
			expect(agentForPrompt(promptName)).toBeDefined();
		}
	});

	it("the agent<->prompt mapping is 1:1 (no duplicate templates)", () => {
		const templates = ALL_AGENTS.map((a) => promptForAgent(a));
		expect(new Set(templates).size).toBe(templates.length);
	});
});
