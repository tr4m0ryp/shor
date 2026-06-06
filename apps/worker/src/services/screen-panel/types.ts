// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Wire types for the N-vote diverse-lens screen panel (T8 + T11).
 *
 * The panel replaces the single adversarial-screen agent per category with N
 * independent lens-voters. Each voter judges one candidate hypothesis and emits
 * a structured `ScreenVerdict`; the panel aggregates the N votes by majority
 * into one `ScreenVerdictEntry` per candidate. The per-category array of entries
 * is written to `{category}_screen_verdicts.json`.
 *
 * STABLE CONTRACT — consumed by task 012 (`services/screen-verdicts`) to apply
 * fail-open routing. The file at `<deliverablesPath>/{category}_screen_verdicts.json`
 * is a JSON array of `ScreenVerdictEntry`. Do NOT change the field names or the
 * `decision` vocabulary without updating the consumer.
 */

/**
 * Per-candidate decision and per-voter verdict. Same vocabulary as the
 * structured `ScreenVerdict.verdict` (single source of truth in
 * `ai/structured/schemas.ts`): a `refute` routes the finding to manual review,
 * `support`/`uncertain` keep it in the emitted set (fail open — never drop what
 * a panel could not affirmatively disprove).
 */
export type ScreenDecision = "refute" | "support" | "uncertain";

/** One voter's recorded ballot on a single candidate id. */
export interface ScreenVote {
	/** 1-based voter ordinal within the panel (mirrors `{{VOTER_INDEX}}`). */
	voter: number;
	/** The analytical lens this voter was assigned (mirrors `{{LENS}}`). */
	lens: string;
	/** The voter's verdict for the candidate. */
	verdict: ScreenDecision;
	/** One-line, voter-supplied justification. */
	reason: string;
}

/**
 * Aggregated verdict for one candidate — the element type of the
 * `{category}_screen_verdicts.json` array.
 */
export interface ScreenVerdictEntry {
	/** Candidate hypothesis id (the queue entry's `ID`, or the synthesized fallback). */
	id: string;
	/** Every voter's ballot, ordered by voter ordinal. */
	votes: ScreenVote[];
	/** Majority decision (ties/splits collapse to `uncertain`; see `decideVotes`). */
	decision: ScreenDecision;
}
