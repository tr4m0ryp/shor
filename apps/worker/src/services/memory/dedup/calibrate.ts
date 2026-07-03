// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Dedup similarity-threshold CALIBRATION (spec T6: "never hardcode the cosine
 * threshold — F1-sweep a labeled pair set per embedding model").
 *
 * The decision boundary is SWEPT from labeled same/different finding pairs, not
 * written as a constant. The default calibration runs over task 017's
 * `SEED_DEDUP_PAIRS`, scored with an F-beta that BIASES TO PRECISION (beta < 1):
 * a false merge folds a real new bug into a resolved cluster — a
 * security-critical false negative — so we prefer a higher, more precise
 * boundary. Callers with real per-model cosine similarities pass their own
 * samples to {@link sweepThreshold}.
 *
 * The 017 seed pairs carry structural features (file/CWE/category), not
 * embeddings, so the default sweep runs on a structural {@link featureSimilarity}
 * proxy — a stand-in signal the real embedding cosine replaces in production.
 * Either way the threshold is DERIVED from labeled data.
 */

import {
	type DedupFeatures,
	type DedupPair,
	SEED_DEDUP_PAIRS,
} from "../../measurement/benchmark/index.js";
import type { CalibratedThreshold } from "./types.js";

/** One labeled sweep sample: a pair similarity + whether they should merge. */
export interface SweepSample {
	readonly similarity: number;
	readonly same: boolean;
}

/** Options for {@link sweepThreshold}. */
export interface SweepOptions {
	/** F-beta weight; < 1 biases to precision (default 0.5). */
	readonly beta?: number;
	/** Grey-band half-width around the boundary for LLM adjudication (default 0.08). */
	readonly margin?: number;
}

const DEFAULT_BETA = 0.5;
const DEFAULT_MARGIN = 0.08;

function round4(n: number): number {
	return Math.round(n * 10000) / 10000;
}

function clamp01(n: number): number {
	if (!Number.isFinite(n)) return 0;
	return n < 0 ? 0 : n > 1 ? 1 : n;
}

/** Precision/recall/F-beta of "predict merge iff similarity >= t". */
function scoreAt(
	samples: readonly SweepSample[],
	t: number,
	beta: number,
): { f: number; precision: number; recall: number } {
	let tp = 0;
	let fp = 0;
	let fn = 0;
	for (const s of samples) {
		const predicted = s.similarity >= t;
		if (s.same && predicted) tp += 1;
		else if (!s.same && predicted) fp += 1;
		else if (s.same && !predicted) fn += 1;
	}
	const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
	const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
	const b2 = beta * beta;
	const denom = b2 * precision + recall;
	const f = denom === 0 ? 0 : ((1 + b2) * precision * recall) / denom;
	return { f, precision, recall };
}

/** Candidate boundaries: midpoints of sorted unique similarities, plus fences. */
function candidateThresholds(samples: readonly SweepSample[]): number[] {
	const uniq = Array.from(
		new Set(samples.map((s) => clamp01(s.similarity))),
	).sort((a, b) => a - b);
	if (uniq.length === 0) return [0.5];
	const out: number[] = [Math.max(0, (uniq[0] as number) - 0.01)];
	for (let i = 0; i < uniq.length - 1; i++) {
		out.push(((uniq[i] as number) + (uniq[i + 1] as number)) / 2);
	}
	out.push(Math.min(1, (uniq[uniq.length - 1] as number) + 0.01));
	return out;
}

/**
 * Sweep the similarity threshold over labeled samples and return the boundary
 * that maximizes F-beta. Ties break toward the HIGHER threshold (precision bias:
 * fewer false merges). The grey band is `threshold ± margin`, clamped to [0,1].
 * Empty input falls back to a neutral 0.5 boundary (documented, never silent).
 */
export function sweepThreshold(
	samples: readonly SweepSample[],
	opts: SweepOptions = {},
): CalibratedThreshold {
	const beta = opts.beta ?? DEFAULT_BETA;
	const margin = opts.margin ?? DEFAULT_MARGIN;
	if (samples.length === 0) {
		return {
			threshold: 0.5,
			greyLow: clamp01(0.5 - margin),
			greyHigh: clamp01(0.5 + margin),
			f1: 0,
			precision: 0,
			recall: 0,
			beta,
		};
	}

	let best: { t: number; f: number; precision: number; recall: number } | null =
		null;
	for (const t of candidateThresholds(samples)) {
		const { f, precision, recall } = scoreAt(samples, t, beta);
		// Strictly-greater keeps the first (lowest) best; `>=` here would flip to
		// the highest — we want the highest among ties, so compare with a small
		// tolerance and prefer the higher t.
		if (
			best === null ||
			f > best.f + 1e-9 ||
			(Math.abs(f - best.f) <= 1e-9 && t > best.t)
		) {
			best = { t, f, precision, recall };
		}
	}

	const b = best as { t: number; f: number; precision: number; recall: number };
	const threshold = clamp01(b.t);
	return {
		threshold: round4(threshold),
		greyLow: round4(clamp01(threshold - margin)),
		greyHigh: round4(clamp01(threshold + margin)),
		f1: round4(scoreAt(samples, threshold, 1).f),
		precision: round4(b.precision),
		recall: round4(b.recall),
		beta,
	};
}

/**
 * Structural similarity proxy in [0,1] for the seed-pair sweep (a stand-in for
 * embedding cosine): a shared file dominates (0.5), the exact CWE adds 0.3, and
 * a shared category adds 0.2. Enough graded signal for the sweep to separate the
 * 017 same/different pairs; production swaps in real cosine per model.
 */
export function featureSimilarity(a: DedupFeatures, b: DedupFeatures): number {
	let s = 0;
	if (a.file && b.file && a.file.toLowerCase() === b.file.toLowerCase())
		s += 0.5;
	if (a.cwe && b.cwe && a.cwe.toUpperCase() === b.cwe.toUpperCase()) s += 0.3;
	if (
		a.category &&
		b.category &&
		a.category.toLowerCase() === b.category.toLowerCase()
	)
		s += 0.2;
	return clamp01(s);
}

/** Adapt the 017 labeled dedup pairs into structural-proxy sweep samples. */
export function seedSamples(
	pairs: readonly DedupPair[] = SEED_DEDUP_PAIRS,
): SweepSample[] {
	return pairs.map((p) => ({
		similarity: featureSimilarity(p.featuresA, p.featuresB),
		same: p.same,
	}));
}

let cached: CalibratedThreshold | null = null;

/**
 * The default dedup calibration — swept from task 017's labeled pairs at import
 * time (memoized). NOT a hardcoded constant: change the seed set or the sweep
 * and the boundary moves. Pass `opts` to force a fresh sweep (bypasses cache).
 */
export function defaultDedupCalibration(
	opts?: SweepOptions,
): CalibratedThreshold {
	if (opts) return sweepThreshold(seedSamples(), opts);
	if (cached === null) cached = sweepThreshold(seedSamples());
	return cached;
}
