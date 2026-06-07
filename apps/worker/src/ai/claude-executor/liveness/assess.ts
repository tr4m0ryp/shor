// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure decision core for the progress-liveness watchdog. No I/O, no /proc — just
 * the rule, so it is exhaustively unit-testable.
 *
 * The principle: NEVER kill on elapsed time. Kill only on PROOF of no progress.
 * A run is "alive" if ANY of three independent signals moved since the last
 * sample — the agent's process-tree CPU, its I/O bytes, or a new stream message.
 * Any movement resets the stillness clock, so a slow-but-working tool can run
 * indefinitely. Only when ALL signals are simultaneously flat for a sustained
 * window do we escalate: a soft kill of the wedged tool first, then a hard abort.
 */

/** A single progress sample of the agent's footprint. */
export interface Footprint {
	/** Cumulative CPU ticks (utime+stime) summed across the agent's process tree. */
	readonly cpuTicks: number;
	/** Cumulative I/O bytes (rchar+wchar — disk AND socket syscalls) across the tree. */
	readonly ioBytes: number;
	/** Wall-clock time of the most recent SDK stream message of any type. */
	readonly lastMessageAt: number;
}

/** Tunable thresholds (all env-overridable via {@link resolveLivenessConfig}). */
export interface LivenessConfig {
	/** How often the out-of-band monitor samples the footprint. */
	readonly sampleIntervalMs: number;
	/** Total stillness before SIGTERM-ing the wedged tool (a gentle nudge). */
	readonly softStallMs: number;
	/** Total stillness before aborting the whole agent (last resort). */
	readonly hardStallMs: number;
	/** CPU-tick delta at/below which movement is treated as housekeeping noise. */
	readonly cpuEpsilonTicks: number;
	/** I/O-byte delta at/below which movement is treated as housekeeping noise. */
	readonly ioEpsilonBytes: number;
}

/** Mutable monitor state across samples. */
export interface LivenessState {
	prev: Footprint | null;
	lastProgressAt: number;
	softFired: boolean;
}

/** What the monitor should do after a sample. */
export type LivenessAction = "none" | "soft-kill" | "hard-abort";

export function createLivenessState(now: number): LivenessState {
	return { prev: null, lastProgressAt: now, softFired: false };
}

/**
 * Decide the action for the current sample and advance `state` in place.
 *
 * The first sample only establishes a baseline (`none`). Thereafter, progress on
 * ANY signal (CPU/I/O above its epsilon, or a newer stream message) resets the
 * stillness clock and clears the soft-fired latch. Only sustained total stillness
 * escalates — soft once at `softStallMs`, then hard at `hardStallMs`.
 */
export function assessLiveness(
	state: LivenessState,
	current: Footprint,
	now: number,
	cfg: LivenessConfig,
): LivenessAction {
	const base = state.prev;
	state.prev = current;

	// First sample: baseline only, never act.
	if (base === null) {
		state.lastProgressAt = now;
		return "none";
	}

	const progressed =
		current.cpuTicks - base.cpuTicks > cfg.cpuEpsilonTicks ||
		current.ioBytes - base.ioBytes > cfg.ioEpsilonBytes ||
		current.lastMessageAt > base.lastMessageAt;

	if (progressed) {
		state.lastProgressAt = now;
		state.softFired = false;
		return "none";
	}

	const stillMs = now - state.lastProgressAt;
	if (stillMs >= cfg.hardStallMs) return "hard-abort";
	if (stillMs >= cfg.softStallMs && !state.softFired) {
		state.softFired = true;
		return "soft-kill";
	}
	return "none";
}

/** Read a positive integer env var, or fall back to `dflt`. */
function intEnv(
	env: NodeJS.ProcessEnv,
	key: string,
	dflt: number,
): number {
	const raw = env[key];
	if (raw === undefined || raw.trim() === "") return dflt;
	const n = Number.parseInt(raw, 10);
	return Number.isFinite(n) && n > 0 ? n : dflt;
}

/**
 * Resolve the config from the environment. Defaults are deliberately GENEROUS —
 * 6 min of total stillness before a soft tool-kill, 10 min before a hard abort —
 * because the hard requirement is to never kill a working long run. A genuinely
 * working tool trips a progress signal within seconds; only a deadlock stays flat
 * this long.
 */
export function resolveLivenessConfig(
	env: NodeJS.ProcessEnv = process.env,
): LivenessConfig {
	return {
		sampleIntervalMs: intEnv(env, "SHOR_LIVENESS_SAMPLE_MS", 15_000),
		softStallMs: intEnv(env, "SHOR_LIVENESS_SOFT_STALL_MS", 360_000),
		hardStallMs: intEnv(env, "SHOR_LIVENESS_HARD_STALL_MS", 600_000),
		cpuEpsilonTicks: intEnv(env, "SHOR_LIVENESS_CPU_EPSILON_TICKS", 2),
		ioEpsilonBytes: intEnv(env, "SHOR_LIVENESS_IO_EPSILON_BYTES", 8_192),
	};
}
