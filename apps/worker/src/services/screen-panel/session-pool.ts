// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Async lease pool over the isolated Playwright sessions the screen panel may
 * drive concurrently.
 *
 * This replaces the old ordinal→session mapping (`sessionForVoter`), which tied a
 * session to a voter's POSITION in its panel: voter #1 of every candidate always
 * wanted `agent1`, so two candidates could never run at once without clobbering
 * each other's browser context. That forced the whole phase serial above the
 * single-candidate level.
 *
 * Here a voter LEASES whatever session is free and RELEASES it when it finishes,
 * so any voter from any candidate/category can run as long as a session is
 * available. The pool size is therefore the GLOBAL cap on concurrently-running
 * voters — set it to the count of distinct isolated sessions the worker
 * provisions for the panel.
 */

import type { PlaywrightSession } from "../../types/agents.js";

/**
 * The isolated sessions the screen panel may drive — `agent1`..`agent5`, the same
 * set the panel has always used (the worker also provisions `agent6`/`agent7`,
 * but those carry the logic / misconfig-web vuln+exploit browser state the
 * exploit phase reuses; the panel leaves them untouched so it can't pollute it).
 */
export const SCREEN_SESSIONS: readonly PlaywrightSession[] = [
	"agent1",
	"agent2",
	"agent3",
	"agent4",
	"agent5",
];

/** A leased session; call {@link SessionLease.release} exactly once when the voter finishes. */
export interface SessionLease {
	readonly session: PlaywrightSession;
	/** Return the session to the pool. Idempotent — safe to call from a `finally`. */
	release(): void;
}

/** A fixed-size lease pool over a set of sessions. */
export interface SessionPool {
	/** Resolve with a free session immediately, or queue (FIFO) until one frees. */
	acquire(): Promise<SessionLease>;
	/** Number of sessions in the pool — the global cap on concurrent leases. */
	readonly size: number;
}

/**
 * Build a lease pool over `sessions`. `acquire` hands back a free session at once,
 * or queues until a `release` frees one — a released session goes straight to the
 * longest-waiting caller (FIFO) rather than sitting idle while a voter waits.
 * Each lease's `release` is idempotent, so a `finally` can call it unconditionally
 * even on a path where the lease was already returned.
 */
export function createSessionPool(
	sessions: readonly PlaywrightSession[] = SCREEN_SESSIONS,
): SessionPool {
	const free: PlaywrightSession[] = [...sessions];
	const waiters: ((session: PlaywrightSession) => void)[] = [];

	const hand = (session: PlaywrightSession): void => {
		const next = waiters.shift();
		if (next !== undefined) next(session);
		else free.push(session);
	};

	const acquire = async (): Promise<SessionLease> => {
		const ready = free.shift();
		const session =
			ready ??
			(await new Promise<PlaywrightSession>((resolve) => {
				waiters.push(resolve);
			}));
		let released = false;
		return {
			session,
			release: () => {
				if (released) return;
				released = true;
				hand(session);
			},
		};
	};

	return { acquire, size: sessions.length };
}
