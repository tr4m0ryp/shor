// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Loop-until-dry + multi-modal lens tests (task 007).
 *
 * Drives `runWithCoverage` through the same injectable-runner seam the canary
 * uses, now also injecting a `FindingsReader`. Verifies: discovery CONTINUES
 * above the breadth floor while new findings arrive and STOPS on the first dry
 * round; the `MAX_DISCOVERY_ROUNDS` ceiling halts (and is logged) when findings
 * never stop; the breadth floor stays a hard MINIMUM; and each continuation
 * cycles a distinct `{{LENS}}` (with optional `{{PARTITION}}`) into the prompt.
 */

import { describe, expect, it } from "vitest";
import type { ClaudePromptResult } from "../../ai/claude-executor.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import {
	buildCoverageFollowUp,
	type PromptRunner,
	runWithCoverage,
} from "../agent-execution/coverage-loop.js";
import type { SkillReader } from "./evaluate.js";
import type { FindingsReader } from "./findings.js";
import {
	DISCOVERY_LENSES,
	MAX_COVERAGE_ROUNDS,
	MAX_DISCOVERY_ROUNDS,
} from "./policy.js";

// ---------------------------------------------------------------------------
// Test seam (mirrors coverage-loop.test.ts / canary.test.ts; do not reach into
// source). A `FindingsReader` is added to script per-round queue lengths.
// ---------------------------------------------------------------------------

/** A successful round (turns > 2 dodges the spending-cap heuristic). */
function okResult(turns = 8): ClaudePromptResult {
	return { success: true, duration: 1, turns, result: "done", model: "m" };
}

/** Faked `runClaudePrompt`: returns the clamped i-th result, records prompts. */
function fakeRunner(results: ClaudePromptResult[]): {
	run: PromptRunner;
	prompts: string[];
	calls: () => number;
} {
	const prompts: string[] = [];
	const run: PromptRunner = (prompt) => {
		const idx = Math.min(prompts.length, results.length - 1);
		prompts.push(prompt);
		return Promise.resolve(results[idx] as ClaudePromptResult);
	};
	return { run, prompts, calls: () => prompts.length };
}

/** Skill reader returning a fixed set for `target` regardless of round. */
function fixedReader(target: AgentName, skills: string[]): SkillReader {
	return (agent) => (agent === target ? skills : []);
}

/** Stepping skill reader: yields perRound[i] on the i-th read (clamped). */
function steppingReader(target: AgentName, perRound: string[][]): SkillReader {
	let reads = 0;
	return (agent) => {
		if (agent !== target) return [];
		const snap = perRound[Math.min(reads, perRound.length - 1)] ?? [];
		reads += 1;
		return snap;
	};
}

/** Findings reader: yields counts[i] (cumulative queue length) on the i-th read. */
function steppingFindings(counts: number[]): FindingsReader {
	let reads = 0;
	return () => {
		const c = counts[Math.min(reads, counts.length - 1)] ?? 0;
		reads += 1;
		return c;
	};
}

/** Logger that records messages per level so a test can assert the cap warning. */
function recordingLogger(): ActivityLogger & {
	warns: string[];
	infos: string[];
} {
	const warns: string[] = [];
	const infos: string[] = [];
	return {
		info: (m) => void infos.push(m),
		warn: (m) => void warns.push(m),
		error: () => {},
		warns,
		infos,
	};
}

const silentLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

// ---------------------------------------------------------------------------
// 1) Convergence: above the floor, a dry round halts discovery.
// ---------------------------------------------------------------------------

describe("runWithCoverage: findings-convergence drives above the floor", () => {
	it("continues while new findings arrive, then stops on the first dry round", async () => {
		// injection-vuln floor is 4 → met from round 0. Findings: 2, then +1, then
		// +0 (dry) → discovery stops the round AFTER the empty one.
		const runner = fakeRunner([okResult()]);
		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
			findingsReader: steppingFindings([2, 3, 3]),
		});

		// round 0 (2 found) → cont 1 (3, +1) → cont 2 (3, +0 dry → halt).
		expect(runner.calls()).toBe(3);
		expect(outcome.rounds).toBe(3);
		expect(outcome.coverage.ok).toBe(true);
	});

	it("does not continue past the floor when round 0 already added nothing", async () => {
		const runner = fakeRunner([okResult()]);
		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
			findingsReader: steppingFindings([0]), // empty queue, no new findings
		});
		expect(runner.calls()).toBe(1);
		expect(outcome.rounds).toBe(1);
	});

	it("falls back to floor-only when there is no findings signal", async () => {
		// No findingsReader/deliverablesPath → above the floor the loop stops at 1.
		const runner = fakeRunner([okResult()]);
		await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
		});
		expect(runner.calls()).toBe(1);
	});
});

// ---------------------------------------------------------------------------
// 2) MAX_DISCOVERY_ROUNDS ceiling halts (and is logged) when findings never dry.
// ---------------------------------------------------------------------------

describe("runWithCoverage: discovery ceiling", () => {
	it("halts at MAX_DISCOVERY_ROUNDS and logs the cap when findings never stop", async () => {
		const runner = fakeRunner([okResult()]);
		const logger = recordingLogger();
		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
			// Strictly increasing → +1 every round, so discovery never converges.
			findingsReader: steppingFindings([1, 2, 3, 4, 5, 6, 7]),
		});

		// One-shot + MAX_DISCOVERY_ROUNDS continuations, then the cap halts it.
		expect(runner.calls()).toBe(MAX_DISCOVERY_ROUNDS + 1);
		expect(outcome.rounds).toBe(MAX_DISCOVERY_ROUNDS + 1);
		expect(outcome.coverage.ok).toBe(true);
		// No silent truncation: the cap is surfaced as a warning.
		expect(logger.warns.some((m) => m.includes("Discovery capped"))).toBe(true);
		expect(
			logger.warns.some((m) => m.includes(`MAX_DISCOVERY_ROUNDS=${MAX_DISCOVERY_ROUNDS}`)),
		).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// 3) The breadth floor remains a hard MINIMUM, independent of findings.
// ---------------------------------------------------------------------------

describe("runWithCoverage: breadth floor stays a minimum", () => {
	it("keeps running to reach the floor even when no findings appear", async () => {
		// Round 0 below floor (1/4) with zero findings: a dry round must NOT halt a
		// below-floor agent — breadth wins until the floor is met.
		const runner = fakeRunner([okResult()]);
		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: steppingReader("injection-vuln", [
				["sqlmap"],
				["sqlmap", "commix", "nosqli", "arjun"],
			]),
			findingsReader: steppingFindings([0, 0]), // never any findings
		});
		expect(runner.calls()).toBe(2); // one-shot + 1 breadth continuation
		expect(outcome.coverage.ok).toBe(true);
		expect(outcome.coverage.ran).toEqual(["sqlmap", "commix", "nosqli", "arjun"]);
	});

	it("bounds a never-reached floor by MAX_COVERAGE_ROUNDS even as findings arrive", async () => {
		// Below floor forever; findings keep arriving but must NOT extend the
		// breadth budget past MAX_COVERAGE_ROUNDS (discovery only drives at/above).
		const runner = fakeRunner([okResult()]);
		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap"]), // 1/2 forever
			findingsReader: steppingFindings([1, 2, 3, 4, 5]),
		});
		expect(runner.calls()).toBe(MAX_COVERAGE_ROUNDS + 1);
		expect(outcome.coverage.ok).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// 4) Lens cycling: each continuation adopts the next discovery lens.
// ---------------------------------------------------------------------------

describe("runWithCoverage: multi-modal lenses", () => {
	it("cycles by-endpoint → by-taint → by-component → by-history across rounds", async () => {
		expect(DISCOVERY_LENSES).toEqual([
			"by-endpoint",
			"by-taint",
			"by-component",
			"by-history",
		]);

		const runner = fakeRunner([okResult()]);
		await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
			findingsReader: steppingFindings([1, 2, 3, 4, 5, 6, 7]),
		});

		// Round 0 is the base prompt; each continuation names the next lens.
		expect(runner.prompts[0]).toBe("BASE");
		expect(runner.prompts[1]).toContain("by-endpoint");
		expect(runner.prompts[2]).toContain("by-taint");
		expect(runner.prompts[3]).toContain("by-component");
		expect(runner.prompts[4]).toContain("by-history");
		// applyPromptContext resolved the placeholder — no literal {{LENS}} leaks.
		for (const p of runner.prompts) expect(p).not.toContain("{{LENS}}");
	});

	it("threads an optional {{PARTITION}} into every follow-up", async () => {
		const runner = fakeRunner([okResult()]);
		await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: fixedReader("injection-vuln", ["sqlmap", "commix", "nosqli", "arjun"]),
			findingsReader: steppingFindings([1, 2, 2]),
			partition: "auth-routes",
		});
		expect(runner.prompts[1]).toContain("auth-routes");
		expect(runner.prompts[1]).toContain("attack-surface slice");
		expect(runner.prompts[1]).not.toContain("{{PARTITION}}");
	});

	it("buildCoverageFollowUp renders the lens and omits the partition line by default", () => {
		const prompt = buildCoverageFollowUp(
			{ ok: true, ran: ["sqlmap"], missing: ["commix"], hardMissing: [], floor: 2 },
			"deliverables/injection-vuln",
			{ lens: "by-taint" },
		);
		expect(prompt).toContain("by-taint");
		expect(prompt).not.toContain("{{LENS}}");
		// No partition supplied → the slice sentence is omitted entirely.
		expect(prompt).not.toContain("attack-surface slice");
	});
});
