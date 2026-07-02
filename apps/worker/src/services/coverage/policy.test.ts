// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import type { AgentName } from "../../types/agents.js";
import { policyFor } from "./evaluate.js";
import { COVERAGE_POLICY, MAX_COVERAGE_ROUNDS } from "./policy.js";

// Vuln floors are half the recommended tool set, rounded up: injection 8→4,
// xss 6→3, the 3-tool categories (auth/ssrf/authz/logic/misconfig-web) →2.
const EXPECTED_MIN_COUNT: Partial<Record<AgentName, number>> = {
	"pre-recon": 2,
	recon: 6,
	"injection-vuln": 4,
	"xss-vuln": 3,
	"auth-vuln": 2,
	"ssrf-vuln": 2,
	"authz-vuln": 2,
	"logic-vuln": 2,
	"misconfig-web-vuln": 2,
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
