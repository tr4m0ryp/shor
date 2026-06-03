// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import type { AgentName } from "../../types/agents.js";
import { policyFor } from "./evaluate.js";
import { COVERAGE_POLICY, MAX_COVERAGE_ROUNDS } from "./policy.js";

const EXPECTED_MIN_COUNT: Partial<Record<AgentName, number>> = {
	"pre-recon": 2,
	recon: 6,
	"injection-vuln": 2,
	"xss-vuln": 2,
	"auth-vuln": 2,
	"ssrf-vuln": 2,
	"authz-vuln": 2,
	"injection-exploit": 1,
	"xss-exploit": 1,
	"auth-exploit": 1,
	"ssrf-exploit": 1,
	"authz-exploit": 1,
};

describe("policy", () => {
	it("MAX_COVERAGE_ROUNDS is 2", () => {
		expect(MAX_COVERAGE_ROUNDS).toBe(2);
	});

	it("has the expected minCount per agent", () => {
		for (const [agent, minCount] of Object.entries(EXPECTED_MIN_COUNT)) {
			expect(COVERAGE_POLICY[agent as AgentName]?.minCount).toBe(minCount);
		}
	});

	it("required is empty for every policied agent (no hard-fails by default)", () => {
		for (const entry of Object.values(COVERAGE_POLICY)) {
			expect(entry?.required).toEqual([]);
		}
	});

	it("synthesis agents have no policy", () => {
		expect(COVERAGE_POLICY.report).toBeUndefined();
		expect(COVERAGE_POLICY["attack-surface"]).toBeUndefined();
		expect(policyFor("report")).toBeUndefined();
		expect(policyFor("attack-surface")).toBeUndefined();
	});

	it("policyFor derives a non-empty candidate pool for policied agents", () => {
		for (const agent of Object.keys(EXPECTED_MIN_COUNT) as AgentName[]) {
			const policy = policyFor(agent);
			expect(policy).toBeDefined();
			expect(policy?.candidates.length).toBeGreaterThan(0);
		}
	});

	it("derived candidate pool is large enough to satisfy the floor", () => {
		for (const agent of Object.keys(EXPECTED_MIN_COUNT) as AgentName[]) {
			const policy = policyFor(agent);
			expect(policy?.candidates.length).toBeGreaterThanOrEqual(
				policy?.minCount ?? 0,
			);
		}
	});
});
