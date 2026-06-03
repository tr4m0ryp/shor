// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Coverage gate + continuation loop (the core breadth fix).
 *
 * After an agent's one-shot run, evaluate tool coverage (services/coverage).
 * When the agent stayed below its breadth floor, build a compact follow-up
 * prompt naming the untried tools and re-invoke the SAME agent — up to
 * `MAX_COVERAGE_ROUNDS` extra rounds — accumulating tool usage in the
 * process-scoped `skillTracker` until the floor is reached or the budget is
 * spent. This converts "only 1 tool used" into "ran the applicable set or
 * justified each skip".
 *
 * The continuation is a FRESH `runClaudePrompt` call: the SDK query is
 * one-shot, so there is no resume. We do NOT replay the prior transcript —
 * the follow-up carries only the compact ran/missing lists plus a pointer to
 * the on-disk deliverables the agent already reads. `skillTracker` is
 * process-scoped, so usage accumulates across rounds automatically; the
 * dispatcher records every tool_use itself, so this loop touches neither the
 * tracker nor the dispatcher.
 *
 * Bounds (defense-in-depth on top of the executor's own spending-cap guard):
 *   - `MAX_COVERAGE_ROUNDS` continuation rounds at most.
 *   - ABORT immediately if a round trips the spending-cap heuristic.
 *   - NEVER loop on a `success: false` round — exit and let the caller's
 *     failure handling (service step 7) classify it.
 */

import type { ModelTier } from "../../ai/models.js";
import type { AuditSession } from "../../audit/index.js";
import type { ClaudePromptResult } from "../../ai/claude-executor.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import { isSpendingCapBehavior } from "../../utils/billing-detection.js";
import {
	type CoverageResult,
	evaluateCoverage,
	MAX_COVERAGE_ROUNDS,
	type SkillReader,
} from "../coverage/index.js";

/**
 * Signature of `runClaudePrompt`, narrowed to the arguments this loop varies
 * between rounds. Injected so the unit test can supply a fake executor without
 * standing up the real Claude SDK.
 */
export type PromptRunner = (
	prompt: string,
) => Promise<ClaudePromptResult>;

/** What `runWithCoverage` returns to the caller (service.ts step 5). */
export interface CoverageLoopOutcome {
	/** The FINAL round's result; later steps (6/9/10) run once on this. */
	readonly result: ClaudePromptResult;
	/** Coverage of the final round — drives the T4 hard-miss bridge. */
	readonly coverage: CoverageResult;
	/** Total rounds executed (1 = one-shot, no continuation fired). */
	readonly rounds: number;
}

/** Inputs for one coverage loop. `runRound` is a 1-arg `runClaudePrompt`. */
export interface CoverageLoopInput {
	readonly agentName: AgentName;
	/** The original (round-0) prompt. */
	readonly basePrompt: string;
	/** Relative path the agent writes/reads its deliverables under. */
	readonly deliverablesSubdir: string;
	readonly modelTier: ModelTier;
	/** Runs one round; the loop only varies the prompt between rounds. */
	readonly runRound: PromptRunner;
	readonly logger: ActivityLogger;
	/** Audit session — referenced only for documentation parity, not mutated here. */
	readonly auditSession?: AuditSession | null;
	/** Injectable coverage reader (defaults to the process-scoped tracker). */
	readonly reader?: SkillReader | undefined;
}

/** Join a tool list compactly, or a sentinel when empty. */
function fmtList(tools: readonly string[]): string {
	return tools.length ? tools.join(", ") : "(none)";
}

/**
 * Build the follow-up prompt for a continuation round.
 *
 * Compact by design: the ran/missing/hardMissing names plus a pointer to the
 * deliverables the agent already reads — NOT the prior transcript (which the
 * one-shot SDK query cannot resume anyway).
 */
export function buildCoverageFollowUp(
	coverage: CoverageResult,
	deliverablesSubdir: string,
): string {
	const ran = fmtList(coverage.ran);
	const missing = fmtList(coverage.missing);
	const requiredLine =
		coverage.hardMissing.length > 0
			? `\nRequired tools that may NOT be skipped: ${fmtList(coverage.hardMissing)}.`
			: "";
	return [
		"Coverage check: your run so far has not met the expected tool breadth",
		`for this phase (floor ${coverage.floor} distinct applicable tools).`,
		"",
		`You ran: ${ran}.`,
		`You did NOT run: ${missing}.`,
		"",
		"Continue against the SAME in-scope target(s) you already analyzed",
		`(your prior findings and notes are on disk under ${deliverablesSubdir}; re-read them, do not start over).`,
		"For each tool you did not run, either run it now against the in-scope",
		"target(s), or add a one-line justification in your deliverable explaining",
		"why it is genuinely inapplicable here. Do not fabricate findings; a",
		"clean negative result is a valid outcome.",
		requiredLine,
	].join("\n");
}

/**
 * Decide whether another continuation round should fire after `coverage`.
 * Centralizes every bound so the loop body reads as a straight line.
 */
function shouldContinue(
	result: ClaudePromptResult,
	coverage: CoverageResult,
	roundsDone: number,
): boolean {
	if (coverage.ok) return false; // floor reached
	if (roundsDone > MAX_COVERAGE_ROUNDS) return false; // budget spent
	if (!result.success) return false; // let failure handling take over
	// Defense-in-depth: a cap trip means further rounds are wasted spend.
	if (isSpendingCapBehavior(result.turns ?? 0, result.result ?? "")) {
		return false;
	}
	return true;
}

/**
 * Run an agent with the coverage continuation loop.
 *
 * Round 0 is the agent's normal one-shot run (caller passes its rendered
 * prompt as `basePrompt`). After each round we evaluate coverage; while the
 * floor is unmet, rounds remain, the round succeeded, and no spending cap was
 * tripped, we re-invoke the SAME agent with a compact follow-up prompt.
 *
 * Returns the FINAL round's result plus its coverage so the caller can run the
 * remaining lifecycle steps once on the converged state, and surface a
 * last-resort `OUTPUT_VALIDATION_FAILED` if `hardMissing` is still non-empty.
 */
export async function runWithCoverage(
	input: CoverageLoopInput,
): Promise<CoverageLoopOutcome> {
	const { agentName, basePrompt, deliverablesSubdir, runRound, logger, reader } =
		input;

	// Round 0: the agent's normal one-shot run.
	let result = await runRound(basePrompt);
	let coverage = evaluateCoverage(agentName, reader);
	let rounds = 1;

	while (shouldContinue(result, coverage, rounds)) {
		logger.info(
			`Coverage below floor for ${agentName} (ran ${coverage.ran.length}/${coverage.floor}); continuation round ${rounds} of ${MAX_COVERAGE_ROUNDS}`,
		);
		const followUp = buildCoverageFollowUp(coverage, deliverablesSubdir);
		result = await runRound(followUp);
		coverage = evaluateCoverage(agentName, reader);
		rounds += 1;
	}

	if (coverage.ok) {
		if (rounds > 1) {
			logger.info(
				`Coverage floor reached for ${agentName} after ${rounds - 1} continuation round(s) (ran ${coverage.ran.length}/${coverage.floor})`,
			);
		}
	} else {
		logger.warn(
			`Coverage still below floor for ${agentName} after ${rounds - 1} continuation round(s) (ran ${coverage.ran.length}/${coverage.floor}, hardMissing=${fmtList(coverage.hardMissing)}); proceeding`,
		);
	}

	return { result, coverage, rounds };
}
