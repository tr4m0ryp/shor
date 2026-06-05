// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Coverage gate + discovery continuation loop (breadth floor + loop-until-dry).
 *
 * After an agent's one-shot run, evaluate tool coverage (services/coverage).
 * Two regimes drive the continuation, both bounded:
 *
 *   - BREADTH (the minimum): while the agent is below its tool-breadth floor,
 *     re-invoke the SAME agent — up to `MAX_COVERAGE_ROUNDS` extra rounds —
 *     naming the untried tools, accumulating tool usage in the process-scoped
 *     `skillTracker` until the floor is reached. Converts "only 1 tool used"
 *     into "ran the applicable set or justified each skip".
 *   - DISCOVERY (loop-until-dry, task 007): ABOVE the floor, keep going while
 *     the LAST round still produced a NEW finding (read from the agent's on-disk
 *     exploitation queue), up to `MAX_DISCOVERY_ROUNDS`. One round that adds
 *     nothing new (K=1) ends discovery; hitting the cap is logged, never silent.
 *     Each discovery round adopts a different `{{LENS}}` (by-endpoint, by-taint,
 *     by-component, by-history) so successive passes attack from a new angle and
 *     accumulate into the same queue.
 *
 * Each continuation is a FRESH `runClaudePrompt` (the SDK query is one-shot, no
 * resume): the follow-up carries only the compact ran/missing lists plus a
 * pointer to the on-disk deliverables. `skillTracker` is process-scoped, so tool
 * usage and findings accumulate across rounds without this loop touching either.
 *
 * Bounds (defense-in-depth on top of the executor's own spending-cap guard):
 *   - `MAX_COVERAGE_ROUNDS` breadth continuations below the floor; at/above the
 *     floor, `MAX_DISCOVERY_ROUNDS` findings continuations at most.
 *   - ABORT immediately if a round trips the spending-cap heuristic.
 *   - NEVER loop on a `success: false` round — exit and let the caller's
 *     failure handling (service step 7) classify it.
 */

import type { ClaudePromptResult } from "../../ai/claude-executor.js";
import type { AuditSession } from "../../audit/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import { isSpendingCapBehavior } from "../../utils/billing-detection.js";
import {
	type CoverageResult,
	DISCOVERY_LENSES,
	evaluateCoverage,
	type FindingsReader,
	makeQueueFindingsReader,
	MAX_COVERAGE_ROUNDS,
	MAX_DISCOVERY_ROUNDS,
	type SkillReader,
} from "../coverage/index.js";
import {
	applyPromptContext,
	type PromptContext,
} from "../prompt-manager/prompt-context.js";

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
	/**
	 * Runs one round; the loop only varies the prompt between rounds, so the
	 * caller bakes the fixed args (repoPath, agentName, auditSession, modelTier,
	 * outputFormat) into this closure.
	 */
	readonly runRound: PromptRunner;
	readonly logger: ActivityLogger;
	/** Audit session — referenced only for documentation parity, not mutated here. */
	readonly auditSession?: AuditSession | null;
	/** Injectable coverage reader (defaults to the process-scoped tracker). */
	readonly reader?: SkillReader | undefined;
	/**
	 * Injectable findings-convergence reader. Defaults to a queue reader over
	 * `deliverablesPath` when that is supplied, else a no-signal reader — the
	 * loop then runs on the tool-breadth floor alone (no findings continuation).
	 * Returns the CURRENT queue length per agent so the loop can diff rounds.
	 */
	readonly findingsReader?: FindingsReader | undefined;
	/**
	 * ABSOLUTE deliverables directory. When present (and no explicit
	 * `findingsReader` is given) the loop reads `{category}_exploitation_queue.json`
	 * here to drive findings-convergence. Reads are confined to this directory.
	 */
	readonly deliverablesPath?: string | undefined;
	/** Optional `{{PARTITION}}` attack-surface slice named in each follow-up. */
	readonly partition?: string | undefined;
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
 *
 * `context` carries the round's `{{LENS}}` (and optional `{{PARTITION}}`): each
 * continuation names its lens so successive rounds attack the SAME target from a
 * different angle and append into the same queue. Values are substituted through
 * `applyPromptContext`, so the loop's per-round `PromptContext` reaches the
 * prompt by the same mechanism the rendered agent prompts use.
 */
export function buildCoverageFollowUp(
	coverage: CoverageResult,
	deliverablesSubdir: string,
	context: PromptContext = {},
): string {
	const ran = fmtList(coverage.ran);
	const missing = fmtList(coverage.missing);
	const requiredLine =
		coverage.hardMissing.length > 0
			? `\nRequired tools that may NOT be skipped: ${fmtList(coverage.hardMissing)}.`
			: "";
	const partitionLine = context.partition
		? "Focus this round on the assigned attack-surface slice: {{PARTITION}}."
		: "";
	const template = [
		"Coverage check: continue discovery against the SAME in-scope target(s).",
		`Tool-breadth floor for this phase: ${coverage.floor} distinct applicable tools.`,
		"",
		`You ran: ${ran}.`,
		`You did NOT run: ${missing}.`,
		"",
		"Attack from a DIFFERENT angle this round — adopt the {{LENS}} lens so this",
		"pass surfaces findings the prior angle(s) missed. Append any NEW findings",
		"to the SAME on-disk queue; a round that finds nothing new ends discovery.",
		partitionLine,
		`Your prior findings and notes are on disk under ${deliverablesSubdir}; re-read them, do not start over.`,
		"For each tool you did not run, either run it now against the in-scope",
		"target(s), or add a one-line justification in your deliverable explaining",
		"why it is genuinely inapplicable here. Do not fabricate findings; a",
		"clean negative result is a valid outcome.",
		requiredLine,
	].join("\n");
	return applyPromptContext(template, context);
}

/** The discovery lens for continuation round `roundsDone` (1-based), cycled. */
function lensForRound(roundsDone: number): string {
	const lenses = DISCOVERY_LENSES;
	const i = ((roundsDone - 1) % lenses.length + lenses.length) % lenses.length;
	return lenses[i] ?? "by-endpoint";
}

/** New findings the latest round produced; `undefined` when there is no signal. */
function diffFindings(prev: number, cur: number | undefined): number | undefined {
	return cur === undefined ? undefined : cur - prev;
}

/**
 * Decide whether another continuation round should fire after `coverage`.
 * Centralizes every bound so the loop body reads as a straight line.
 *
 * Two regimes, both bounded:
 *   - BELOW the breadth floor (`!coverage.ok`): keep going to reach breadth (the
 *     MINIMUM), bounded by `MAX_COVERAGE_ROUNDS` continuations.
 *   - AT/ABOVE the floor: findings-convergence drives — continue only while the
 *     last round produced at least one NEW finding, bounded by
 *     `MAX_DISCOVERY_ROUNDS` continuations. One empty round (K=1) ends discovery.
 *     `newFindings === undefined` means "no findings signal" (non-vuln agent or
 *     unwired path), so reaching the floor is enough and the loop stops.
 *
 * A failed or spending-capped round always stops, regardless of regime.
 */
function shouldContinue(
	result: ClaudePromptResult,
	coverage: CoverageResult,
	roundsDone: number,
	newFindings: number | undefined,
): boolean {
	if (!result.success) return false; // let failure handling take over
	// Defense-in-depth: a cap trip means further rounds are wasted spend.
	if (isSpendingCapBehavior(result.turns ?? 0, result.result ?? "")) {
		return false;
	}
	// Breadth floor is the MINIMUM: stay below-floor logic until it is met.
	if (!coverage.ok) return roundsDone <= MAX_COVERAGE_ROUNDS;
	// At/above the floor: findings-convergence is the driver, capped.
	if (roundsDone > MAX_DISCOVERY_ROUNDS) return false; // discovery ceiling
	return (newFindings ?? 0) >= 1; // a new finding last round → keep going
}

/**
 * Run an agent with the coverage + discovery continuation loop.
 *
 * Round 0 is the agent's normal one-shot run. After each round we evaluate
 * coverage AND read the agent's findings count; while `shouldContinue` holds
 * (below floor → breadth; at/above floor → a new finding last round), we
 * re-invoke the SAME agent with a compact, lens-tagged follow-up that cycles a
 * distinct `{{LENS}}` so the re-runs attack from different angles.
 *
 * Returns the FINAL round's result plus its coverage so the caller runs the rest
 * of the lifecycle once on the converged state (and surfaces a last-resort
 * `OUTPUT_VALIDATION_FAILED` if `hardMissing` is still non-empty).
 */
export async function runWithCoverage(
	input: CoverageLoopInput,
): Promise<CoverageLoopOutcome> {
	const {
		agentName,
		basePrompt,
		deliverablesSubdir,
		runRound,
		logger,
		reader,
		partition,
	} = input;

	// Findings-convergence reader: explicit injection > queue reader over the
	// deliverables dir > a no-signal reader (loop then runs on the floor alone).
	const readFindings: FindingsReader =
		input.findingsReader ??
		(input.deliverablesPath !== undefined
			? makeQueueFindingsReader(input.deliverablesPath)
			: () => undefined);

	// Round 0: the agent's normal one-shot run.
	let result = await runRound(basePrompt);
	let coverage = evaluateCoverage(agentName, reader);
	let rounds = 1;
	let prevFindings = 0; // the queue is empty before round 0
	let curFindings = readFindings(agentName);
	let newFindings = diffFindings(prevFindings, curFindings);

	while (shouldContinue(result, coverage, rounds, newFindings)) {
		const lens = lensForRound(rounds);
		const driver = coverage.ok ? "discovery" : "breadth";
		logger.info(
			`Coverage continuation for ${agentName} (${driver}; ran ${coverage.ran.length}/${coverage.floor}, newFindings=${newFindings ?? "n/a"}); round ${rounds}, lens=${lens}`,
		);
		const followUp = buildCoverageFollowUp(coverage, deliverablesSubdir, {
			lens,
			...(partition !== undefined && { partition }),
		});
		result = await runRound(followUp);
		coverage = evaluateCoverage(agentName, reader);
		prevFindings = curFindings ?? prevFindings;
		curFindings = readFindings(agentName);
		newFindings = diffFindings(prevFindings, curFindings);
		rounds += 1;
	}

	// No silent truncation: note when the discovery ceiling — not a dry round —
	// is what stopped the loop (floor met, last round still produced findings).
	if (
		result.success &&
		coverage.ok &&
		rounds > MAX_DISCOVERY_ROUNDS &&
		(newFindings ?? 0) >= 1
	) {
		logger.warn(
			`Discovery capped for ${agentName} at MAX_DISCOVERY_ROUNDS=${MAX_DISCOVERY_ROUNDS} ` +
				`with findings still arriving (last round +${newFindings}); stopping without claiming convergence`,
		);
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
