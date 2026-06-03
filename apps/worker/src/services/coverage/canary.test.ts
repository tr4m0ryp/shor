// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Regression canary for the tool-coverage breadth fix (task 007).
 *
 * This is the DETERMINISTIC, CI-able guard that locks in the behavior the
 * coverage loop exists to enforce, WITHOUT a live target, model, or any tool:
 *
 *   1. End-to-end loop canary — drive `runWithCoverage` through the SAME
 *      injectable-runner seam `coverage-loop.test.ts` uses (a faked
 *      `runClaudePrompt` + a stepping `SkillReader`). The agent runs ONE tool
 *      on round 0 (below floor) and more on the re-prompt; the loop must reach
 *      the floor and report the correct ran / missing / ok.
 *
 *   2. Static policy invariants — recon floor >= 6, every `*-vuln` >= 2, every
 *      `*-exploit` >= 1 with its derived candidate pool containing that
 *      category's exploit tool (e.g. injection-exploit -> sqlmap); synthesis
 *      agents carry no policy; `required` is empty everywhere (breadth is driven
 *      by minCount + the loop, never by a hard-required tool).
 *
 * The companion live harness (`scripts/coverage-canary.ts`) is intentionally
 * NOT a `*.test.ts`, so `vitest run` never touches the network here.
 */

import { describe, expect, it } from "vitest";
import type { ClaudePromptResult } from "../../ai/claude-executor.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import {
	type PromptRunner,
	runWithCoverage,
} from "../agent-execution/coverage-loop.js";
import { policyFor } from "./evaluate.js";
import type { SkillReader } from "./evaluate.js";
import { COVERAGE_POLICY } from "./policy.js";

// ---------------------------------------------------------------------------
// Test seam, mirrored from coverage-loop.test.ts (do NOT reach into source).
// ---------------------------------------------------------------------------

/** Silent logger so the canary stays quiet but the loop's calls still run. */
const silentLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

/** A successful round (turns > 2 dodges the spending-cap heuristic). */
function okResult(turns = 8): ClaudePromptResult {
	return { success: true, duration: 1, turns, result: "done", model: "m" };
}

/**
 * A faked `runClaudePrompt`: returns the i-th scripted result (clamped to the
 * last) and records every prompt it was handed.
 */
function fakeRunner(
	results: ClaudePromptResult[],
): { run: PromptRunner; prompts: string[]; calls: () => number } {
	const prompts: string[] = [];
	const run: PromptRunner = (prompt) => {
		const idx = Math.min(prompts.length, results.length - 1);
		prompts.push(prompt);
		return Promise.resolve(results[idx] as ClaudePromptResult);
	};
	return { run, prompts, calls: () => prompts.length };
}

/**
 * A stateful reader yielding the round-N skill set: index 0 before any
 * continuation, advancing one step per read. Mirrors how the real
 * `skillTracker` accumulates usage across rounds (evaluator reads once/round).
 */
function steppingReader(target: AgentName, perRound: string[][]): SkillReader {
	let reads = 0;
	return (agent) => {
		if (agent !== target) return [];
		const snapshot = perRound[Math.min(reads, perRound.length - 1)] ?? [];
		reads += 1;
		return snapshot;
	};
}

// ---------------------------------------------------------------------------
// 1) End-to-end loop canary: one tool on round 0, more on the re-prompt.
// ---------------------------------------------------------------------------

describe("coverage canary: continuation reaches the floor", () => {
	it("recon climbs from 1 tool to the floor over re-prompts (ran/missing/ok correct)", async () => {
		// recon floor is 6. Round 0 runs ONLY httpx (1/6, below floor); each
		// re-prompt adds tools until the 6th lands and the loop exits.
		const policy = policyFor("recon");
		if (!policy) throw new Error("recon must have a policy");
		expect(policy.floor).toBeGreaterThanOrEqual(6);

		// Six real recon candidates, fed in cumulatively across rounds.
		const six = ["httpx", "katana", "naabu", "nmap", "subfinder", "dnsx"];
		expect(six.every((t) => policy.candidates.includes(t))).toBe(true);
		const perRound = [
			six.slice(0, 1), // round 0: only httpx (below floor)
			six.slice(0, 4), // continuation 1: 4 tools (still below)
			six.slice(0, 6), // continuation 2: 6 tools (floor reached)
		];

		const runner = fakeRunner([okResult()]);
		const reader = steppingReader("recon", perRound);

		const outcome = await runWithCoverage({
			agentName: "recon",
			basePrompt: "BASE",
			deliverablesSubdir: "deliverables/recon",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		// 3 rounds total: one-shot + two continuations to climb 1 -> 4 -> 6.
		expect(runner.calls()).toBe(3);
		expect(outcome.rounds).toBe(3);
		expect(outcome.coverage.ok).toBe(true);
		expect(outcome.coverage.ran).toEqual(six);
		expect(outcome.coverage.ran.length).toBeGreaterThanOrEqual(policy.floor);
		// Round 0 saw the base prompt; the re-prompt named the missing tools.
		expect(runner.prompts[0]).toBe("BASE");
		expect(runner.prompts[1]).toContain("did NOT run");
	});

	it("an exploit agent that runs ONE category tool on the re-prompt reaches its floor", async () => {
		// injection-exploit floor is 1. Round 0 runs nothing applicable; the
		// re-prompt fires sqlmap -> floor reached -> loop exits.
		const runner = fakeRunner([okResult()]);
		const reader = steppingReader("injection-exploit", [[], ["sqlmap"]]);

		const outcome = await runWithCoverage({
			agentName: "injection-exploit",
			basePrompt: "BASE",
			deliverablesSubdir: "deliverables/injection-exploit",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		expect(runner.calls()).toBe(2);
		expect(outcome.rounds).toBe(2);
		expect(outcome.coverage.ok).toBe(true);
		expect(outcome.coverage.ran).toEqual(["sqlmap"]);
		expect(outcome.coverage.floor).toBe(1);
		expect(outcome.coverage.missing).not.toContain("sqlmap");
	});

	it("reports missing + not-ok when the agent never climbs past one tool", async () => {
		// injection-vuln floor is 2 but only sqlmap ever runs: the canary must
		// observe a NOT-ok result with the rest of the pool reported missing.
		const runner = fakeRunner([okResult()]);
		const reader = steppingReader("injection-vuln", [["sqlmap"]]);

		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "deliverables/injection-vuln",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		expect(outcome.coverage.ok).toBe(false);
		expect(outcome.coverage.ran).toEqual(["sqlmap"]);
		expect(outcome.coverage.ran.length).toBeLessThan(outcome.coverage.floor);
		expect(outcome.coverage.missing.length).toBeGreaterThan(0);
		expect(outcome.coverage.missing).not.toContain("sqlmap");
	});
});

// ---------------------------------------------------------------------------
// 2) Static policy invariants (the breadth floor the loop enforces).
// ---------------------------------------------------------------------------

/** vuln-phase agents and their per-category minimum (>= 2). */
const VULN_AGENTS: readonly AgentName[] = [
	"injection-vuln",
	"xss-vuln",
	"auth-vuln",
	"ssrf-vuln",
	"authz-vuln",
];

/**
 * exploit-phase agents and one tool that MUST appear in the derived candidate
 * pool for that category (proves the candidate derivation is wired, not empty).
 */
const EXPLOIT_AGENT_TOOL: ReadonlyArray<readonly [AgentName, string]> = [
	["injection-exploit", "sqlmap"],
	["xss-exploit", "dalfox"],
	["auth-exploit", "hydra"],
	["ssrf-exploit", "ssrfmap"],
	["authz-exploit", "authz-recipe"],
];

describe("coverage canary: static policy invariants", () => {
	it("recon floor is at least 6 with a candidate pool that can satisfy it", () => {
		const policy = policyFor("recon");
		expect(policy).toBeDefined();
		expect(policy?.minCount).toBeGreaterThanOrEqual(6);
		expect(policy?.candidates.length).toBeGreaterThanOrEqual(6);
	});

	it("every *-vuln agent has minCount >= 2 and a pool that meets it", () => {
		for (const agent of VULN_AGENTS) {
			const policy = policyFor(agent);
			expect(policy, `policy for ${agent}`).toBeDefined();
			expect(policy?.minCount, `minCount for ${agent}`).toBeGreaterThanOrEqual(2);
			expect(
				policy?.candidates.length,
				`candidate pool for ${agent}`,
			).toBeGreaterThanOrEqual(policy?.minCount ?? 0);
		}
	});

	it("every *-exploit agent has minCount >= 1 and its category tool in candidates", () => {
		for (const [agent, tool] of EXPLOIT_AGENT_TOOL) {
			const policy = policyFor(agent);
			expect(policy, `policy for ${agent}`).toBeDefined();
			expect(policy?.minCount, `minCount for ${agent}`).toBeGreaterThanOrEqual(1);
			expect(
				policy?.candidates,
				`candidates for ${agent} must include ${tool}`,
			).toContain(tool);
		}
	});

	it("required is empty for every policied agent (no hard-required tool)", () => {
		for (const [agent, thresholds] of Object.entries(COVERAGE_POLICY)) {
			expect(thresholds?.required, `required for ${agent}`).toEqual([]);
			expect(
				policyFor(agent as AgentName)?.required,
				`derived required for ${agent}`,
			).toEqual([]);
		}
	});

	it("synthesis agents carry no policy (nothing to cover)", () => {
		expect(COVERAGE_POLICY.report).toBeUndefined();
		expect(COVERAGE_POLICY["attack-surface"]).toBeUndefined();
		expect(policyFor("report")).toBeUndefined();
		expect(policyFor("attack-surface")).toBeUndefined();
	});
});
