// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from "vitest";
import type { AgentName } from "../../types/agents.js";
import { evaluateCoverage, type SkillReader } from "./evaluate.js";

/** Build a deterministic reader that returns `skills` for `target`, else []. */
function readerFor(target: AgentName, skills: string[]): SkillReader {
	return (agent) => (agent === target ? skills : []);
}

describe("evaluateCoverage", () => {
	it("returns ok with empty arrays for an agent with no policy", () => {
		const result = evaluateCoverage("report", () => ["sqlmap", "nmap"]);
		expect(result).toEqual({
			ok: true,
			ran: [],
			missing: [],
			hardMissing: [],
			floor: 0,
		});
	});

	it("attack-surface (no policy) is always ok", () => {
		expect(evaluateCoverage("attack-surface", () => []).ok).toBe(true);
	});

	it("fails when fewer than minCount candidate tools ran", () => {
		// injection-vuln floor is 4 (half of 8 recommended); one tool used.
		const result = evaluateCoverage(
			"injection-vuln",
			readerFor("injection-vuln", ["sqlmap"]),
		);
		expect(result.ok).toBe(false);
		expect(result.ran).toEqual(["sqlmap"]);
		expect(result.floor).toBe(4);
		expect(result.hardMissing).toEqual([]);
		expect(result.missing).not.toContain("sqlmap");
		expect(result.missing.length).toBeGreaterThan(0);
	});

	it("passes when at least minCount candidate tools ran", () => {
		const result = evaluateCoverage(
			"injection-vuln",
			readerFor("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
		);
		expect(result.ok).toBe(true);
		expect(result.ran).toEqual(["sqlmap", "commix", "nosqli", "arjun"]);
		expect(result.hardMissing).toEqual([]);
	});

	it("policies logic-vuln and misconfig-web with a floor (was unpoliced → floor 0)", () => {
		// logic-vuln recommended set is 3 tools → floor 2; running nothing fails.
		const none = evaluateCoverage("logic-vuln", () => []);
		expect(none.ok).toBe(false);
		expect(none.floor).toBe(2);
		const met = evaluateCoverage(
			"logic-vuln",
			readerFor("logic-vuln", ["semgrep", "arjun"]),
		);
		expect(met.ok).toBe(true);
	});

	it("counts only candidate tools toward coverage (ignores off-policy tools)", () => {
		// nmap is not an injection-vuln candidate; it must not count.
		const result = evaluateCoverage(
			"injection-vuln",
			readerFor("injection-vuln", ["sqlmap", "nmap"]),
		);
		expect(result.ran).toEqual(["sqlmap"]);
		expect(result.ran).not.toContain("nmap");
		expect(result.ok).toBe(false);
	});

	it("ran + missing partition the candidate pool exactly", () => {
		const result = evaluateCoverage(
			"recon",
			readerFor("recon", ["httpx", "nmap", "ffuf"]),
		);
		const recombined = new Set([...result.ran, ...result.missing]);
		// No overlap and union covers every candidate.
		expect(result.ran.length + result.missing.length).toBe(recombined.size);
		for (const tool of result.ran) expect(result.missing).not.toContain(tool);
	});

	it("recon needs 6 distinct candidates to pass", () => {
		const five = ["httpx", "katana", "naabu", "nmap", "subfinder"];
		const six = [...five, "dnsx"];
		expect(evaluateCoverage("recon", readerFor("recon", five)).ok).toBe(false);
		expect(evaluateCoverage("recon", readerFor("recon", six)).ok).toBe(true);
	});

	it("exploit agents pass with a single candidate tool (floor 1)", () => {
		const result = evaluateCoverage(
			"injection-exploit",
			readerFor("injection-exploit", ["sqlmap"]),
		);
		expect(result.floor).toBe(1);
		expect(result.ok).toBe(true);
	});

	it("an agent that ran nothing fails its floor", () => {
		const result = evaluateCoverage("recon", () => []);
		expect(result.ok).toBe(false);
		expect(result.ran).toEqual([]);
		expect(result.missing.length).toBeGreaterThan(0);
	});

	it("dedupes nothing it shouldn't: duplicate usage still counts once", () => {
		// Reader returns a tool twice; Set de-dup means it counts as one.
		const result = evaluateCoverage(
			"injection-vuln",
			readerFor("injection-vuln", ["sqlmap", "sqlmap"]),
		);
		expect(result.ran).toEqual(["sqlmap"]);
	});

	describe("below-floor shortfall signal (T4)", () => {
		it("attaches a structured shortfall when below the floor", () => {
			// injection-vuln floor is 2; one tool used → below floor.
			const result = evaluateCoverage(
				"injection-vuln",
				readerFor("injection-vuln", ["sqlmap"]),
			);
			expect(result.ok).toBe(false);
			expect(result.shortfall).toEqual({
				belowFloor: true,
				ranTools: 1,
				requiredFloor: 2,
				missing: result.missing,
			});
		});

		it("omits the shortfall when the floor is met", () => {
			const result = evaluateCoverage(
				"injection-vuln",
				readerFor("injection-vuln", ["sqlmap", "commix"]),
			);
			expect(result.ok).toBe(true);
			expect(result.shortfall).toBeUndefined();
		});

		it("omits the shortfall for an agent with no policy", () => {
			// "report" has no policy → ok with no shortfall.
			expect(evaluateCoverage("report", () => []).shortfall).toBeUndefined();
		});

		it("shortfall.ranTools / requiredFloor mirror ran.length / floor", () => {
			// recon floor is 6; only two distinct candidates exercised.
			const result = evaluateCoverage(
				"recon",
				readerFor("recon", ["httpx", "nmap"]),
			);
			expect(result.ok).toBe(false);
			expect(result.shortfall?.ranTools).toBe(result.ran.length);
			expect(result.shortfall?.requiredFloor).toBe(result.floor);
		});
	});
});
