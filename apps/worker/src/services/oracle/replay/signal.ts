// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pure decision logic for the oracle: the read-only safety gate, the signal
 * matcher, and the outcome → verdict reducer. No I/O — exhaustively unit-tested.
 */

import type {
	ExecOutcome,
	ExpectedSignal,
	OracleDisposition,
	Poc,
} from "./types.js";

/** Idempotent, side-effect-free HTTP methods safe to re-fire. */
const READ_ONLY_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD"]);

/**
 * Read-only safety gate. ONLY idempotent GET/HEAD requests — or a PoC the agent
 * explicitly vouched as side-effect-free via `safe: true` — may be auto-replayed.
 * Everything else is treated as state-changing and is NEVER re-fired (the runner
 * classifies it `not_replayable`).
 */
export function isReadOnly(poc: Poc): boolean {
	if (poc.safe === true) return true;
	if (poc.kind === "http") {
		const method = (poc.request?.method ?? "GET").toUpperCase();
		return READ_ONLY_METHODS.has(method);
	}
	// browser / oob replays are re-fired only when explicitly vouched safe above.
	return false;
}

/**
 * Does the observation satisfy the declared signal? Pure and total:
 *   - `status`     — the response status equals the expected code.
 *   - `reflection` — the expected payload appears (reflected) in the body.
 *   - `data`       — the expected sensitive-data marker appears in the body.
 *   - `oob`        — an out-of-band callback was observed for the token.
 * A non-observed outcome never matches.
 */
export function matchSignal(expected: ExpectedSignal, obs: ExecOutcome): boolean {
	if (!obs.observed) return false;
	switch (expected.type) {
		case "status":
			return obs.status !== undefined && String(obs.status) === String(expected.match).trim();
		case "reflection":
		case "data":
			return typeof obs.body === "string" && obs.body.includes(String(expected.match));
		case "oob":
			return obs.oobObserved === true;
		default:
			return false;
	}
}

/** A replay verdict for one PoC. */
export interface Verdict {
	disposition: OracleDisposition;
	/** Short human-readable explanation of what the oracle observed. */
	signal: string;
	/** True when the target rate-limited us (drives the runner's backoff). */
	rateLimited: boolean;
}

/** Short description of the observed signal, for logs / audit. */
function describeSignal(expected: ExpectedSignal, obs: ExecOutcome, matched: boolean): string {
	const state = matched ? "matched" : "absent";
	let detail = "";
	if (obs.observed) {
		if (expected.type === "status") detail = `status=${obs.status}`;
		else if (expected.type === "oob") detail = `oob=${obs.oobObserved === true}`;
		else detail = `body~"${String(expected.match).slice(0, 24)}"`;
	}
	return `${expected.type} ${state}${detail ? ` (${detail})` : ""}`;
}

/**
 * Reduce an executor outcome to an authoritative oracle verdict.
 *   - observed + signal match  → `exploited`
 *   - observed + signal absent → `blocked` (reached it cleanly; exploit did not reproduce)
 *   - rate-limited             → `not_replayable` + backoff
 *   - transport error / unwired→ `not_replayable` (markdown parse remains the fallback)
 */
export function decide(poc: Poc, outcome: ExecOutcome): Verdict {
	if (!outcome.observed) {
		if (outcome.reason === "rate_limited") {
			return {
				disposition: "not_replayable",
				signal: "rate-limited (HTTP 429); backing off",
				rateLimited: true,
			};
		}
		return {
			disposition: "not_replayable",
			signal: outcome.detail ?? outcome.reason,
			rateLimited: false,
		};
	}
	const matched = matchSignal(poc.expected_signal, outcome);
	return {
		disposition: matched ? "exploited" : "blocked",
		signal: describeSignal(poc.expected_signal, outcome, matched),
		rateLimited: false,
	};
}

/** One lower-privilege replay of an authz PoC, for the differential premise check. */
export interface DifferentialOutcome {
	label: string;
	/** false for the anonymous (no-auth) replay; true for a real lower-priv identity. */
	authenticated: boolean;
	outcome: ExecOutcome;
}

/**
 * Decide the authz `premise_valid` (T1) from replays under lower-privilege identities:
 *   - `true`      — a LOWER-privilege identity (authenticated OR anonymous) reproduced
 *                   the success signal ⇒ a real privilege boundary was crossed.
 *   - `false`     — a lower AUTHENTICATED identity was genuinely tried (observed) and
 *                   NONE reproduced it ⇒ privileged-only (the scan-0007 false-positive
 *                   class: admin doing an admin thing).
 *   - `undefined` — inconclusive: only anonymous could be tried and it did not reproduce
 *                   (anonymous failing never disproves an "any authenticated user" claim).
 * Fail-open by design: uncertainty yields `undefined` and never demotes a finding.
 */
export function decidePremise(poc: Poc, lower: readonly DifferentialOutcome[]): boolean | undefined {
	let triedAuthenticated = false;
	for (const d of lower) {
		if (d.outcome.observed && matchSignal(poc.expected_signal, d.outcome)) return true;
		if (d.authenticated && d.outcome.observed) triedAuthenticated = true;
	}
	return triedAuthenticated ? false : undefined;
}
