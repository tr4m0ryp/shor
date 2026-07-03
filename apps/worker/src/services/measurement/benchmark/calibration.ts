// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Proof-confidence calibration METRICS (spec T15). Given (predicted probability,
 * observed TP/FP) samples, report a reliability diagram + Expected/Max Calibration
 * Error + Brier score — the fourth scorecard axis: "does a 0.9-confidence finding
 * actually hold 0.9 of the time?" This MEASURES calibration; task 008 FITS the
 * curve. Pure over injected samples — no IO, no clock.
 */

/** One (predicted, label) point: label 1 = true positive, 0 = false positive. */
export interface CalibrationSample {
	readonly predicted: number;
	readonly label: 0 | 1;
}

/** One reliability bin over a confidence interval. */
export interface CalibrationBin {
	/** Half-open bin bounds [lo, hi) (the top bin includes 1.0). */
	readonly lo: number;
	readonly hi: number;
	readonly count: number;
	/** Mean predicted probability of samples in the bin (null when empty). */
	readonly meanPredicted: number | null;
	/** Observed TP fraction in the bin (null when empty). */
	readonly observed: number | null;
	/** |meanPredicted - observed| (null when empty). */
	readonly gap: number | null;
}

/** Calibration summary over a sample set. */
export interface CalibrationReport {
	readonly samples: number;
	readonly bins: readonly CalibrationBin[];
	/** Expected Calibration Error: count-weighted mean bin gap. */
	readonly ece: number | null;
	/** Max Calibration Error: worst bin gap. */
	readonly mce: number | null;
	/** Brier score: mean squared error of predicted vs label (lower is better). */
	readonly brier: number | null;
	/** Base rate: overall TP fraction. */
	readonly baseRate: number | null;
}

function round4(n: number): number {
	return Math.round(n * 10000) / 10000;
}

function clamp01(n: number): number {
	if (!Number.isFinite(n)) return 0;
	return n < 0 ? 0 : n > 1 ? 1 : n;
}

/** Bin index for a probability in [0,1] across `binCount` equal bins. */
function binIndex(p: number, binCount: number): number {
	const idx = Math.floor(clamp01(p) * binCount);
	return idx >= binCount ? binCount - 1 : idx;
}

/**
 * Compute the calibration report over `samples` with `binCount` equal-width bins
 * (default 10). Empty input yields a well-formed report with null aggregates.
 */
export function computeCalibration(
	samples: readonly CalibrationSample[],
	binCount = 10,
): CalibrationReport {
	const bins = Math.max(1, Math.floor(binCount));
	const sumP: number[] = new Array(bins).fill(0);
	const sumY: number[] = new Array(bins).fill(0);
	const n: number[] = new Array(bins).fill(0);

	let brierSum = 0;
	let positives = 0;
	for (const s of samples) {
		const p = clamp01(s.predicted);
		const y = s.label === 1 ? 1 : 0;
		const i = binIndex(p, bins);
		sumP[i] = (sumP[i] ?? 0) + p;
		sumY[i] = (sumY[i] ?? 0) + y;
		n[i] = (n[i] ?? 0) + 1;
		brierSum += (p - y) * (p - y);
		positives += y;
	}

	const total = samples.length;
	const binReports: CalibrationBin[] = [];
	let eceNum = 0;
	let mce: number | null = null;
	for (let i = 0; i < bins; i++) {
		const lo = round4(i / bins);
		const hi = round4((i + 1) / bins);
		const c = n[i] ?? 0;
		if (c === 0) {
			binReports.push({ lo, hi, count: 0, meanPredicted: null, observed: null, gap: null });
			continue;
		}
		const meanPredicted = round4((sumP[i] ?? 0) / c);
		const observed = round4((sumY[i] ?? 0) / c);
		const gap = round4(Math.abs(meanPredicted - observed));
		binReports.push({ lo, hi, count: c, meanPredicted, observed, gap });
		eceNum += c * gap;
		mce = mce === null ? gap : Math.max(mce, gap);
	}

	return {
		samples: total,
		bins: binReports,
		ece: total > 0 ? round4(eceNum / total) : null,
		mce,
		brier: total > 0 ? round4(brierSum / total) : null,
		baseRate: total > 0 ? round4(positives / total) : null,
	};
}
