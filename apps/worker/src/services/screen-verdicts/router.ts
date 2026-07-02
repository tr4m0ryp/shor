// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-category routing for the screen step. The screen is a PRIORITIZER, not a
 * gate (spec T14): only a confident majority-`refute` rejects; everything else
 * flows through to exploitation, where the executable oracle is the real arbiter.
 */

import type {
	FindingCategory,
	NormalizedVuln,
} from "../../job/findings/types.js";
import type { ScreenVerdictEntry, ScreenVote } from "../screen-panel/types.js";

/**
 * Pick the justification to carry onto a refuted finding: prefer the first
 * REFUTING voter's reason (it explains the rejection), else any non-empty
 * reason, else the empty string.
 */
function refuteReason(votes: readonly ScreenVote[]): string {
	for (const v of votes) {
		if (v.verdict === "refute" && v.reason.trim()) return v.reason;
	}
	for (const v of votes) {
		if (v.reason.trim()) return v.reason;
	}
	return "";
}

/** Synthesize a terminal rejected entry for an id the raw queue no longer carries. */
function synthesizeRejected(
	category: FindingCategory,
	id: string,
	reason: string,
): NormalizedVuln {
	return {
		category,
		id,
		raw: { ID: id },
		disposition: "unverified_screen_rejected",
		evidenceText: reason,
	};
}

/** Stamp a queue entry rejected unless a live PoC already proved it. */
function markRejected(match: NormalizedVuln, reason: string): void {
	if (match.disposition === "exploited") return; // a live PoC is never demoted
	match.disposition = "unverified_screen_rejected";
	if (reason.trim()) match.evidenceText = reason;
}

/**
 * Apply panel verdicts (fail open) for one category, mutating `vulns` in place.
 *
 * Routing table:
 *   - `refute`    → `unverified_screen_rejected` (terminal; the ONLY decision
 *                   that rejects). Carries a refuting voter's reason; synthesizes
 *                   an entry when the raw queue dropped the id.
 *   - `uncertain` → `screen_uncertain` (non-terminal; flows to exploitation).
 *   - `support`   → left unchanged (stays `queued`; flows to exploitation).
 *
 * An `exploited` finding (a live PoC) is NEVER demoted, for any decision. A
 * non-terminal `uncertain` only promotes a still-unresolved `queued` hypothesis,
 * so it never clobbers an exploitation outcome already on record.
 */
export function applyVerdictEntries(
	vulns: NormalizedVuln[],
	category: FindingCategory,
	entries: readonly ScreenVerdictEntry[],
): void {
	for (const entry of entries) {
		const match = vulns.find(
			(v) => v.category === category && v.id === entry.id,
		);
		if (entry.decision === "refute") {
			const reason = refuteReason(entry.votes);
			if (match) markRejected(match, reason);
			else vulns.push(synthesizeRejected(category, entry.id, reason));
			continue;
		}
		if (entry.decision === "uncertain") {
			if (match && match.disposition === "queued") {
				match.disposition = "screen_uncertain";
			}
			continue;
		}
		// entry.decision === "support": leave as queued — flows to exploitation.
	}
}

/**
 * Backward-compatible legacy path: a category with no panel verdicts but a
 * `{category}_screen_rejected.json` audit file. Mirrors the pre-panel behavior
 * verbatim — every refuted id (except a live `exploited`) becomes
 * `unverified_screen_rejected`, synthesizing an entry when the queue dropped it.
 */
export function applyLegacyRejections(
	vulns: NormalizedVuln[],
	category: FindingCategory,
	byId: ReadonlyMap<string, string>,
): void {
	for (const [id, reason] of byId) {
		const match = vulns.find((v) => v.category === category && v.id === id);
		if (match) markRejected(match, reason);
		else vulns.push(synthesizeRejected(category, id, reason));
	}
}
