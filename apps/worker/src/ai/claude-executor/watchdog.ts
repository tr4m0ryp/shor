// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Stale-loop watchdog for the Claude Agent SDK message stream.
 *
 * Detects two failure patterns and forces the loop to exit:
 *
 *   1. **Background-task feedback loop.** The agent launched a detached shell
 *      job (`bash -c "... &"`, `nohup`, `sleep 2000 && cat /tmp/foo`) that
 *      keeps emitting stdout. Each batch returns as a tool_result, the agent
 *      acknowledges "the assessment is already complete", and the cycle
 *      repeats indefinitely — paying for tokens and blocking the workflow.
 *      We detect this by counting consecutive assistant turns whose text
 *      content matches stagnation phrases and contains no new save-deliverable
 *      call.
 *
 *   2. **Post-completion loitering.** The agent saved the deliverable but kept
 *      generating turns afterwards (e.g. responding to lingering background
 *      output, or going in circles). We expire after a turn budget past the
 *      last save-deliverable.
 *
 * On trigger, the watchdog:
 *   - Logs the trigger reason and current turn count.
 *   - Force-kills child shell processes (bash, sh, sleep) older than 60s so
 *     the brute-force / lingering jobs cannot keep emitting output.
 *   - Returns `{ stale: true }` so the caller can `break` the stream loop.
 */

import { execFileSync } from "node:child_process";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** Patterns that indicate the agent is acknowledging a stale tool result instead of making progress. */
const STAGNATION_PHRASES: readonly RegExp[] = [
	/\bbackground task notification\b/i,
	/\bbackground task\b.*\b(stale|already|complete)\b/i,
	/\bauxiliary (task|brute)\b/i,
	/\bbrute[- ]force.*\b(stale|killed|sigkill|exit 144|complete)\b/i,
	/\bSSRF assessment is (already )?complete\b/i,
	/\bassessment is (fully )?complete.*no further action\b/i,
	/\balready (documented|complete|saved)\b/i,
	/\bdeliverable (is|has been) (already )?(saved|complete)\b/i,
	/\bno further action (needed|required)\b/i,
];

const MAX_STAGNATION_STREAK = 8;
const MAX_TURNS_AFTER_SAVE = 25;

export interface WatchdogState {
	stagnationStreak: number;
	savedDeliverableTurn: number | null;
	triggered: boolean;
}

export function createWatchdogState(): WatchdogState {
	return { stagnationStreak: 0, savedDeliverableTurn: null, triggered: false };
}

/**
 * Update watchdog state from an assistant message's plain-text content and tool-call list.
 * Caller passes both — the extraction logic lives in the dispatcher.
 */
export function recordAssistantTurn(
	state: WatchdogState,
	turnCount: number,
	assistantText: string,
	toolCommands: readonly string[],
): void {
	// 1. Detect a save-deliverable call so we can budget the post-save grace period.
	if (state.savedDeliverableTurn === null) {
		for (const cmd of toolCommands) {
			if (/save-deliverable\b/i.test(cmd)) {
				state.savedDeliverableTurn = turnCount;
				break;
			}
		}
	}

	// 2. Count stagnation streak. Reset to 0 the moment the agent says something
	//    substantive (no stagnation phrase match in this turn's text).
	const matched = STAGNATION_PHRASES.some((re) => re.test(assistantText));
	state.stagnationStreak = matched ? state.stagnationStreak + 1 : 0;
}

/**
 * Returns the reason string if the watchdog should fire on this turn, or null otherwise.
 */
export function shouldTrigger(
	state: WatchdogState,
	turnCount: number,
): string | null {
	if (state.triggered) return null;
	if (state.stagnationStreak >= MAX_STAGNATION_STREAK) {
		return `${state.stagnationStreak} consecutive stagnation turns (max ${MAX_STAGNATION_STREAK})`;
	}
	if (
		state.savedDeliverableTurn !== null &&
		turnCount - state.savedDeliverableTurn >= MAX_TURNS_AFTER_SAVE
	) {
		return `${turnCount - state.savedDeliverableTurn} turns since save-deliverable (max ${MAX_TURNS_AFTER_SAVE})`;
	}
	return null;
}

/**
 * Kill long-running shell descendants in the worker container so the agent's
 * background tool calls cannot keep emitting tool_result messages after we
 * break out of the loop.
 *
 * Targets:
 *   - any `sleep <N>` older than 60s
 *   - any `bash` / `sh` whose command line contains telltale patterns
 *     (`wordlist`, `brute`, `hydra`, `/tmp/bf_`, `nohup`)
 *
 * Conservative: never kills PID 1 (tini), never kills processes owned by uids
 * other than our own, never touches the Node SDK subprocess (matched by
 * `node` in argv[0]). Failures are swallowed — the watchdog must not throw.
 */
export function killStaleAgentChildren(logger: ActivityLogger): void {
	const ranAndLogged = (label: string, args: readonly string[]): void => {
		try {
			execFileSync(args[0] ?? "", args.slice(1), {
				stdio: "pipe",
				timeout: 5000,
			});
			logger.info(`watchdog: ${label}`);
		} catch (err) {
			// pkill exits 1 when nothing matched; that's not a failure for us.
			const exitCode = (err as { status?: number } | null)?.status;
			if (exitCode !== 1) {
				const msg = err instanceof Error ? err.message : String(err);
				logger.warn(`watchdog: ${label} failed: ${msg}`);
			}
		}
	};

	ranAndLogged("kill bf_ background scripts", [
		"pkill",
		"-9",
		"-f",
		"/tmp/bf_",
	]);
	ranAndLogged("kill wordlist/brute/hydra patterns", [
		"pkill",
		"-9",
		"-f",
		"(wordlist|brute|hydra|/tmp/bg_)",
	]);
	ranAndLogged("kill nohup-detached jobs", [
		"pkill",
		"-9",
		"-f",
		"\\bnohup\\b",
	]);
	ranAndLogged("kill long sleep guards", [
		"pkill",
		"-9",
		"-f",
		"^sleep ([6-9][0-9]{2}|[0-9]{4,})",
	]);
	ranAndLogged("clean /tmp/bf_* artifacts", [
		"sh",
		"-c",
		"rm -f /tmp/bf_* /tmp/bg_* 2>/dev/null; true",
	]);
}

/**
 * Fire the watchdog. Idempotent on `state.triggered`.
 */
export function fire(
	state: WatchdogState,
	reason: string,
	logger: ActivityLogger,
): void {
	if (state.triggered) return;
	state.triggered = true;
	logger.warn(
		`watchdog: stale loop detected — ${reason}; killing child shells and breaking stream`,
	);
	killStaleAgentChildren(logger);
}
