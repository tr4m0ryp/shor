// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-run regression tracking (spec T15). Reduce each per-release
 * {@link Scorecard} to a compact {@link ScorecardEntry}, append to a
 * {@link ScorecardHistory}, and diff the last two entries so a drop in recall /
 * dedup-precision or a rise in FP-rate / calibration-error surfaces as an explicit
 * regression. Comparisons across DIFFERENT benchmarks are flagged invalid — you
 * only prove "better over time" over the same yardstick. Pure, no IO.
 */

import type { Scorecard } from "./scorecard.js";

/** Small margin below which a metric delta is treated as noise, not a change. */
export const REGRESSION_EPSILON = 0.001;

/** A per-release scorecard reduced to its headline numbers. */
export interface ScorecardEntry {
	readonly release: string;
	readonly generated_at: string;
	readonly benchmark_id: string;
	readonly recall: number | null;
	readonly false_positive_rate: number | null;
	readonly dedup_precision: number | null;
	readonly ece: number | null;
	readonly brier: number | null;
}

/** An ordered log of scorecard entries (oldest first). */
export interface ScorecardHistory {
	readonly entries: readonly ScorecardEntry[];
}

/** The signed deltas + a verdict from comparing two entries. */
export interface RegressionReport {
	readonly from: string;
	readonly to: string;
	/** False when the two entries used different benchmarks (not comparable). */
	readonly same_benchmark: boolean;
	readonly recall_delta: number | null;
	readonly false_positive_rate_delta: number | null;
	readonly dedup_precision_delta: number | null;
	readonly ece_delta: number | null;
	readonly regressed: boolean;
	readonly reasons: readonly string[];
}

/** Reduce a full scorecard to a history entry. */
export function toEntry(scorecard: Scorecard, generatedAt: string): ScorecardEntry {
	return {
		release: scorecard.release,
		generated_at: generatedAt,
		benchmark_id: scorecard.benchmark_id,
		recall: scorecard.recall.recall,
		false_positive_rate: scorecard.false_positive.false_positive_rate,
		dedup_precision: scorecard.dedup.dedup_precision,
		ece: scorecard.calibration.ece,
		brier: scorecard.calibration.brier,
	};
}

/** Append an entry to a history (returns a new history; input is untouched). */
export function appendEntry(
	history: ScorecardHistory,
	entry: ScorecardEntry,
): ScorecardHistory {
	return { entries: [...history.entries, entry] };
}

/** Signed delta of two nullable metrics (null when either side is null). */
function delta(prev: number | null, curr: number | null): number | null {
	if (prev === null || curr === null) return null;
	return Math.round((curr - prev) * 10000) / 10000;
}

/**
 * Compare two entries. A metric where MORE is better (recall, dedup-precision)
 * regresses when it drops; one where LESS is better (fp-rate, ECE) regresses when
 * it rises — each past {@link REGRESSION_EPSILON}. A benchmark mismatch is itself a
 * regression reason (the comparison is not valid).
 */
export function compareEntries(
	prev: ScorecardEntry,
	curr: ScorecardEntry,
): RegressionReport {
	const sameBenchmark = prev.benchmark_id === curr.benchmark_id;
	const recallDelta = delta(prev.recall, curr.recall);
	const fprDelta = delta(prev.false_positive_rate, curr.false_positive_rate);
	const dedupDelta = delta(prev.dedup_precision, curr.dedup_precision);
	const eceDelta = delta(prev.ece, curr.ece);

	const reasons: string[] = [];
	if (!sameBenchmark) {
		reasons.push(
			`benchmark changed (${prev.benchmark_id} -> ${curr.benchmark_id}); metrics are not comparable.`,
		);
	}
	if (sameBenchmark) {
		if (recallDelta !== null && recallDelta < -REGRESSION_EPSILON)
			reasons.push(`recall dropped by ${(-recallDelta).toFixed(4)}.`);
		if (fprDelta !== null && fprDelta > REGRESSION_EPSILON)
			reasons.push(`false-positive rate rose by ${fprDelta.toFixed(4)}.`);
		if (dedupDelta !== null && dedupDelta < -REGRESSION_EPSILON)
			reasons.push(`dedup precision dropped by ${(-dedupDelta).toFixed(4)}.`);
		if (eceDelta !== null && eceDelta > REGRESSION_EPSILON)
			reasons.push(`calibration error (ECE) rose by ${eceDelta.toFixed(4)}.`);
	}

	return {
		from: prev.release,
		to: curr.release,
		same_benchmark: sameBenchmark,
		recall_delta: recallDelta,
		false_positive_rate_delta: fprDelta,
		dedup_precision_delta: dedupDelta,
		ece_delta: eceDelta,
		regressed: reasons.length > 0,
		reasons,
	};
}

/** Diff the last two entries of a history (null when fewer than two exist). */
export function latestRegression(
	history: ScorecardHistory,
): RegressionReport | null {
	const n = history.entries.length;
	if (n < 2) return null;
	return compareEntries(
		history.entries[n - 2] as ScorecardEntry,
		history.entries[n - 1] as ScorecardEntry,
	);
}
