// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Threshold calibration (spec T6: "never hardcode the cosine threshold").
 * Under test: the boundary is DERIVED by sweeping labeled samples (not a
 * constant), it separates the 017 seed pairs at F1=1, it is precision-biased,
 * and it MOVES when the labeled data moves (the proof it is not a literal).
 */

import { describe, expect, it } from "vitest";
import { SEED_DEDUP_PAIRS } from "../../measurement/benchmark/index.js";
import {
	defaultDedupCalibration,
	featureSimilarity,
	seedSamples,
	sweepThreshold,
	type SweepSample,
} from "./calibrate.js";

describe("sweepThreshold: derived, not constant", () => {
	it("places the boundary between the diff-max and same-min similarities", () => {
		const samples: SweepSample[] = [
			{ similarity: 0.95, same: true },
			{ similarity: 0.9, same: true },
			{ similarity: 0.7, same: true },
			{ similarity: 0.2, same: false },
			{ similarity: 0.1, same: false },
			{ similarity: 0.0, same: false },
		];
		const cal = sweepThreshold(samples);
		expect(cal.threshold).toBeGreaterThan(0.2);
		expect(cal.threshold).toBeLessThanOrEqual(0.7);
		expect(cal.f1).toBe(1);
	});

	it("MOVES when the labeled data moves (proves it is not a literal)", () => {
		const low = sweepThreshold([
			{ similarity: 0.3, same: true },
			{ similarity: 0.05, same: false },
		]);
		const high = sweepThreshold([
			{ similarity: 0.9, same: true },
			{ similarity: 0.6, same: false },
		]);
		expect(low.threshold).not.toBe(high.threshold);
		expect(high.threshold).toBeGreaterThan(low.threshold);
	});

	it("is precision-biased (beta<1): default beta below 1", () => {
		expect(sweepThreshold([{ similarity: 0.8, same: true }]).beta).toBeLessThan(1);
	});

	it("prefers the higher boundary among tying thresholds (fewer false merges)", () => {
		// Perfect separation over (0.2 .. 0.8): several thresholds tie at F=1; the
		// precision-bias tie-break keeps the highest (closest to the same-min).
		const cal = sweepThreshold([
			{ similarity: 0.8, same: true },
			{ similarity: 0.2, same: false },
		]);
		expect(cal.threshold).toBeGreaterThan(0.4);
	});

	it("degrades to a documented neutral boundary on empty input", () => {
		expect(sweepThreshold([]).threshold).toBe(0.5);
	});
});

describe("defaultDedupCalibration: over the 017 seed pairs", () => {
	it("separates every seed same/different pair (F1=1, precision=1)", () => {
		const cal = defaultDedupCalibration();
		expect(cal.f1).toBe(1);
		expect(cal.precision).toBe(1);
		expect(cal.recall).toBe(1);
		// The threshold is a swept value strictly inside the separating gap.
		expect(cal.threshold).toBeGreaterThan(0.2);
		expect(cal.threshold).toBeLessThanOrEqual(0.7);
		// Grey band brackets the boundary.
		expect(cal.greyLow).toBeLessThan(cal.threshold);
		expect(cal.greyHigh).toBeGreaterThan(cal.threshold);
	});

	it("every seed same-pair scores above the boundary; every diff-pair below", () => {
		const cal = defaultDedupCalibration();
		for (const p of SEED_DEDUP_PAIRS) {
			const s = featureSimilarity(p.featuresA, p.featuresB);
			if (p.same) expect(s).toBeGreaterThanOrEqual(cal.threshold);
			else expect(s).toBeLessThan(cal.threshold);
		}
	});
});

describe("featureSimilarity: structural proxy", () => {
	it("scores an exact same-file/CWE/category pair at 1.0", () => {
		expect(
			featureSimilarity(
				{ file: "svc/EffectService.cs", cwe: "CWE-918", category: "ssrf" },
				{ file: "svc/EffectService.cs", cwe: "CWE-918", category: "ssrf" },
			),
		).toBe(1);
	});

	it("scores an unrelated ssrf/xss pair at 0", () => {
		expect(
			featureSimilarity(
				{ file: "svc/EffectService.cs", cwe: "CWE-918", category: "ssrf" },
				{ file: "web/MarkdownRenderer.tsx", cwe: "CWE-79", category: "xss" },
			),
		).toBe(0);
	});

	it("seedSamples maps every 017 pair to a (similarity,label)", () => {
		expect(seedSamples()).toHaveLength(SEED_DEDUP_PAIRS.length);
	});
});
