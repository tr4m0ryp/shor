// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The out-of-band liveness monitor: a timer (independent of the SDK message
 * stream) that samples the agent's process-tree footprint and escalates only on
 * sustained, multi-signal NON-progress. This catches the failure the turn/text
 * watchdog structurally cannot — a SILENT hang inside a tool call, where the SDK
 * emits no further messages so the stream-driven watchdog never even runs.
 *
 * Escalation is two-step and deliberately blast-radius-minimal:
 *   1. soft-kill — SIGTERM the wedged tool leaves only; the SDK runtime survives,
 *      so the agent sees a failed tool and can recover. A false positive here
 *      costs ONE tool result, not the lane.
 *   2. hard-abort — abort the whole agent via its AbortController (and reap any
 *      stray background shells). The caller turns this into a fail-open,
 *      retryable result, so the lane finishes instead of hanging the run.
 */

import { randomUUID } from "node:crypto";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { killStaleAgentChildren } from "../watchdog.js";
import {
	assessLiveness,
	createLivenessState,
	type Footprint,
	type LivenessConfig,
	resolveLivenessConfig,
} from "./assess.js";
import { findAgentRoots, procAvailable, signalPids, walkTree } from "./proc.js";

/** Env var injected into the SDK subprocess so we can scope its process tree. */
export const LIVENESS_TOKEN_ENV = "SHOR_LIVENESS_ID";

export interface LivenessMonitor {
	/** Unique per-agent token; inject `{ [tokenEnvVar]: token }` into the SDK env. */
	readonly token: string;
	readonly tokenEnvVar: string;
	/** Call on every stream message — registers stream progress. */
	markMessage(): void;
	/** Stop the timer (idempotent). Call in a `finally`. */
	stop(): void;
}

export interface LivenessMonitorArgs {
	/** Tripped on hard-abort to terminate the SDK query. */
	controller: AbortController;
	logger: ActivityLogger;
	/** Records the reason so the caller can raise a typed, retryable failure. */
	onHardAbort: (reason: string) => void;
	/** Overrides for tests; defaults from the environment. */
	config?: LivenessConfig;
	now?: () => number;
}

/**
 * Start the monitor. On a host without `/proc` (non-Linux dev) it is a NO-OP —
 * we never kill on stream-silence alone, since that is exactly the false-kill we
 * are designed to avoid. Returns a token to tag the SDK env with.
 */
export function startLivenessMonitor(args: LivenessMonitorArgs): LivenessMonitor {
	const token = randomUUID();
	const cfg = args.config ?? resolveLivenessConfig();
	const now = args.now ?? ((): number => Date.now());
	const noop: LivenessMonitor = {
		token,
		tokenEnvVar: LIVENESS_TOKEN_ENV,
		markMessage: () => {},
		stop: () => {},
	};

	if (!procAvailable()) {
		args.logger.info(
			"liveness-watchdog: /proc unavailable; progress-based hang detection disabled",
		);
		return noop;
	}

	const state = createLivenessState(now());
	let lastMessageAt = now();
	let roots: number[] = [];

	const tick = (): void => {
		// Resolve this agent's tree root once the SDK subprocess is up.
		if (roots.length === 0) {
			roots = findAgentRoots(token);
			if (roots.length === 0) return; // not spawned yet — wait
		}
		const tree = walkTree(roots);
		if (tree.members.length === 0) return; // tree exited; the query will end on its own

		const footprint: Footprint = {
			cpuTicks: tree.cpuTicks,
			ioBytes: tree.ioBytes,
			lastMessageAt,
		};
		const action = assessLiveness(state, footprint, now(), cfg);

		if (action === "soft-kill") {
			args.logger.warn(
				`liveness-watchdog: no CPU, I/O, or stream progress for ${Math.round(
					cfg.softStallMs / 1000,
				)}s; SIGTERM-ing ${tree.leaves.length} wedged tool leaf process(es)`,
			);
			signalPids(tree.leaves, "SIGTERM", args.logger);
		} else if (action === "hard-abort") {
			const reason = `liveness timeout — agent made no CPU, I/O, or stream progress for ${Math.round(
				cfg.hardStallMs / 1000,
			)}s`;
			args.logger.error(`liveness-watchdog: ${reason}; aborting agent`);
			args.onHardAbort(reason);
			killStaleAgentChildren(args.logger);
			args.controller.abort();
		}
	};

	const handle = setInterval(tick, cfg.sampleIntervalMs);
	// Never let the watchdog timer keep the process alive on its own.
	if (typeof handle.unref === "function") handle.unref();

	return {
		token,
		tokenEnvVar: LIVENESS_TOKEN_ENV,
		markMessage: () => {
			lastMessageAt = now();
		},
		stop: () => clearInterval(handle),
	};
}
