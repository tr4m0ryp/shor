// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
