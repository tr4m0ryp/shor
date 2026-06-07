// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ClaudePromptResult } from "../../ai/claude-executor.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import type { SkillReader } from "../coverage/index.js";
import { MAX_COVERAGE_ROUNDS } from "../coverage/index.js";
import {
	buildCoverageFollowUp,
	type PromptRunner,
	runWithCoverage,
} from "./coverage-loop.js";

/** Swallow logger so tests stay quiet but the loop's calls are exercised. */
const silentLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

/** A successful round with the given turn count (default >2 to dodge the cap heuristic). */
function okResult(turns = 8): ClaudePromptResult {
	return { success: true, duration: 1, turns, result: "done", model: "m" };
}

/**
 * A faked `runClaudePrompt`: returns the i-th scripted result (clamped to the
 * last) and records every prompt it was handed, so a test can assert the
 * follow-up was injected.
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
 * A stateful skill reader that yields the round-N skill set: index 0 before any
 * continuation, advancing one step each time it is read. Mirrors how the real
 * `skillTracker` accumulates tool usage across rounds (the evaluator reads it
 * once per round).
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

/** A reader that always returns the same skills regardless of round. */
function fixedReader(target: AgentName, skills: string[]): SkillReader {
	return (agent) => (agent === target ? skills : []);
}

describe("buildCoverageFollowUp", () => {
	it("names ran + missing tools and points at the deliverables dir", () => {
		const prompt = buildCoverageFollowUp(
			{
				ok: false,
				ran: ["sqlmap"],
				missing: ["commix", "nosqli"],
				hardMissing: [],
				floor: 2,
			},
			"deliverables/injection-vuln",
		);
		expect(prompt).toContain("sqlmap");
		expect(prompt).toContain("commix");
		expect(prompt).toContain("nosqli");
		expect(prompt).toContain("did NOT run");
		expect(prompt).toContain("deliverables/injection-vuln");
		// No required tools → no "may NOT be skipped" clause.
		expect(prompt).not.toContain("may NOT be skipped");
	});

	it("adds a hard-requirement clause when required tools are missing", () => {
		const prompt = buildCoverageFollowUp(
			{
				ok: false,
				ran: [],
				missing: ["sqlmap"],
				hardMissing: ["sqlmap"],
				floor: 1,
			},
			"deliverables/x",
		);
		expect(prompt).toContain("may NOT be skipped");
		expect(prompt).toContain("sqlmap");
	});
});

describe("runWithCoverage", () => {
	it("re-invokes the agent until the floor is reached, then exits", async () => {
		// injection-vuln floor is 2. Round 0 runs only sqlmap (below floor); the
		// follow-up round adds commix → floor reached → loop exits.
		const runner = fakeRunner([okResult()]);
		const reader = steppingReader("injection-vuln", [
			["sqlmap"],
			["sqlmap", "commix", "nosqli", "arjun"],
		]);

		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "deliverables/injection-vuln",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		// Exactly two rounds: the one-shot + one continuation.
		expect(runner.calls()).toBe(2);
		expect(outcome.rounds).toBe(2);
		expect(outcome.coverage.ok).toBe(true);
		expect(outcome.coverage.ran).toEqual(["sqlmap", "commix"]);
		// Round 0 got the base prompt; round 1 got the injected follow-up.
		expect(runner.prompts[0]).toBe("BASE");
		expect(runner.prompts[1]).toContain("did NOT run");
		expect(runner.prompts[1]).toContain("commix");
	});

	it("does not continue when round 0 already meets the floor", async () => {
		const runner = fakeRunner([okResult()]);
		const reader = fixedReader("injection-vuln", ["sqlmap", "commix"]);

		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		expect(runner.calls()).toBe(1);
		expect(outcome.rounds).toBe(1);
		expect(outcome.coverage.ok).toBe(true);
	});

	it("is bounded: stops after MAX_COVERAGE_ROUNDS even if the floor is never met", async () => {
		// Floor never reached (only sqlmap ever runs); the loop must still halt.
		const runner = fakeRunner([okResult()]);
		const reader = fixedReader("injection-vuln", ["sqlmap"]);

		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		// One-shot + MAX_COVERAGE_ROUNDS continuations, then give up.
		expect(runner.calls()).toBe(MAX_COVERAGE_ROUNDS + 1);
		expect(outcome.rounds).toBe(MAX_COVERAGE_ROUNDS + 1);
		expect(outcome.coverage.ok).toBe(false);
	});

	it("aborts immediately when a round trips the spending-cap heuristic", async () => {
		// Low turns + billing text → isSpendingCapBehavior(true): no continuation.
		const capped: ClaudePromptResult = {
			success: true,
			duration: 1,
			turns: 1,
			result: "You have reached your spending cap; usage resets soon.",
			model: "m",
		};
		const runner = fakeRunner([capped]);
		const reader = fixedReader("injection-vuln", ["sqlmap"]); // below floor

		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		expect(runner.calls()).toBe(1);
		expect(outcome.rounds).toBe(1);
		expect(outcome.coverage.ok).toBe(false);
	});

	it("never loops on a success:false round (lets failure handling take over)", async () => {
		const failed: ClaudePromptResult = {
			success: false,
			duration: 1,
			turns: 5,
			error: "boom",
			retryable: true,
		};
		const runner = fakeRunner([failed]);
		const reader = fixedReader("injection-vuln", ["sqlmap"]); // below floor

		const outcome = await runWithCoverage({
			agentName: "injection-vuln",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader,
		});

		expect(runner.calls()).toBe(1);
		expect(outcome.result.success).toBe(false);
	});

	it("no-policy agents (report) run exactly once", async () => {
		const runner = fakeRunner([okResult()]);
		const outcome = await runWithCoverage({
			agentName: "report",
			basePrompt: "BASE",
			deliverablesSubdir: "d",
			logger: silentLogger,
			runRound: runner.run,
			reader: () => [],
		});
		expect(runner.calls()).toBe(1);
		expect(outcome.coverage.ok).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// T4 last-resort hard-miss bridge. `failAgent` does git/audit I/O, so we mock
// it and assert ONLY the decision `failOnHardMissing` owns: empty hardMissing
// → null (proceed); non-empty → a retryable OUTPUT_VALIDATION_FAILED failure.
// ---------------------------------------------------------------------------
const failAgentMock = vi.hoisted(() => vi.fn());
vi.mock("../agent-execution-internal.js", () => ({
	failAgent: failAgentMock,
}));

describe("failOnHardMissing", () => {
	beforeEach(() => {
		failAgentMock.mockReset();
		failAgentMock.mockResolvedValue({ ok: false, error: "FAIL" });
	});

	it("returns null and never fails when there are no hard misses", async () => {
		const { failOnHardMissing } = await import("./post-execution.js");
		const out = await failOnHardMissing(
			"injection-vuln",
			"/tmp/d",
			{} as never,
			silentLogger,
			1,
			okResult(),
			{ ok: false, ran: ["sqlmap"], missing: ["commix"], hardMissing: [], floor: 2 },
		);
		expect(out).toBeNull();
		expect(failAgentMock).not.toHaveBeenCalled();
	});

	it("fails retryably with OUTPUT_VALIDATION_FAILED when a required tool was skipped", async () => {
		const { failOnHardMissing } = await import("./post-execution.js");
		const out = await failOnHardMissing(
			"injection-vuln",
			"/tmp/d",
			{} as never,
			silentLogger,
			1,
			okResult(),
			{ ok: false, ran: [], missing: ["sqlmap"], hardMissing: ["sqlmap"], floor: 1 },
		);
		expect(out).not.toBeNull();
		expect(failAgentMock).toHaveBeenCalledTimes(1);
		const call = failAgentMock.mock.calls[0];
		if (!call) throw new Error("failAgent was not called");
		const opts = call[4];
		expect(opts.errorCode).toBe("OUTPUT_VALIDATION_FAILED");
		expect(opts.retryable).toBe(true);
		expect(opts.context.hardMissing).toEqual(["sqlmap"]);
	});
});
