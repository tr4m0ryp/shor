// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Model safety-refusal detection.
 *
 * The offensive agents (recon / vuln-* / exploit-*) drive the model against
 * security-sensitive instructions. Even under an authorized-assessment preamble
 * the model can occasionally decline the task as "cyber content" and return a
 * short refusal *instead of doing the work* — the SDK call still reports
 * success, so without this the refusal masquerades as "no findings": the
 * exploit lane produces no evidence and a real finding is stranded at `firm`
 * (analysed but never live-validated) rather than promoted to `confirmed`.
 *
 * This mirrors {@link ./billing-detection.ts} (which catches the analogous
 * spending-cap short-circuit): a low turn count plus a refusal phrase. A refusal
 * is treated as RETRYABLE — the retry re-runs with the strengthened
 * authorization context (`prompts/shared/_authorization.txt`); a refusal that
 * persists fails the lane, which honestly demotes the lane's findings to
 * `unverified_out_of_scope` rather than emitting them as if tested.
 */

/**
 * Phrases a refusal opens with. Kept specific to first-person decline language
 * so a *legitimate* write-up ("the WAF blocked this, so I cannot provide a
 * working payload") does not match — that is real work, and the turn-count gate
 * in {@link isRefusalBehavior} screens it out regardless.
 */
export const REFUSAL_TEXT_PATTERNS = [
	"i can't help with",
	"i cannot help with",
	"i can't assist with",
	"i cannot assist with",
	"i'm not able to help",
	"i am not able to help",
	"i won't be able to help",
	"i'm unable to assist",
	"i am unable to assist",
	"i can't provide",
	"i cannot provide",
	"i can't engage",
	"i cannot engage",
	"i must decline",
	"i have to decline",
	"i'm not comfortable",
	"i am not comfortable",
	"cannot in good conscience",
	"against my guidelines",
	"i'm sorry, but i can't",
	"i'm sorry but i can't",
] as const;

/** True when `text` opens with / contains a first-person refusal phrase. */
export function matchesRefusalPattern(text: string): boolean {
	const lower = text.toLowerCase();
	return REFUSAL_TEXT_PATTERNS.some((pattern) => lower.includes(pattern));
}

/**
 * Behavioral heuristic for a model refusal.
 *
 * Combines two signals, exactly as the spending-cap heuristic does:
 *   1. Very low turn count (<= 2) — the agent bailed instead of working.
 *   2. The result text contains a refusal phrase.
 *
 * The turn gate is load-bearing: an agent that actually ran the assessment
 * takes many turns, so a "cannot provide" buried in genuine evidence prose is
 * not flagged.
 */
export function isRefusalBehavior(turns: number, resultText: string): boolean {
	if (turns > 2) {
		return false;
	}
	return matchesRefusalPattern(resultText);
}
