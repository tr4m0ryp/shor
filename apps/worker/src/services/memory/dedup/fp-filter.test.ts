// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * FP auto-filter (spec T6, valid-vuln-yield). Under test:
 *  - a confirmed FP (exact fingerprint) is DEMOTED, never dropped;
 *  - a confident fuzzy near-miss is demoted; a weak one is not (precision bias);
 *  - a lookup failure fails OPEN (no demotion, finding retained);
 *  - the finding set count is invariant — nothing is ever deleted.
 */

import { describe, expect, it } from "vitest";
import {
	demoteConfidence,
	filterFalsePositives,
	type FpFilterDeps,
	type FpMemoryHit,
	type FpMemoryNearHit,
	type FpScope,
} from "./fp-filter.js";
import type { CalibratedThreshold, DedupCandidate } from "./types.js";

const SCOPE: FpScope = { tenantId: "t1", projectId: "p1" };
const CAL: CalibratedThreshold = {
	threshold: 0.5,
	greyLow: 0.4,
	greyHigh: 0.6,
	f1: 1,
	precision: 1,
	recall: 1,
	beta: 0.5,
};

function candidate(id: string, fingerprint: string, confidence: string, vecText?: number[]): DedupCandidate {
	return { finding: { id, fingerprint, confidence, validation_note: "" }, ...(vecText ? { vecText } : {}) };
}

describe("filterFalsePositives: exact fingerprint", () => {
	it("DEMOTES a confirmed FP without dropping it", async () => {
		const remembered = new Map<string, FpMemoryHit>([
			["fp-1", { fingerprint: "fp-1", decision: "refuted", reason: "god-mode identity" }],
		]);
		const deps: FpFilterDeps = {
			scope: SCOPE,
			calibration: CAL,
			async findByFingerprint(_s, fp) {
				return remembered.get(fp) ?? null;
			},
		};
		const input = [
			candidate("a", "fp-1", "confirmed"),
			candidate("b", "fp-2", "firm"),
			candidate("c", "fp-3", "tentative"),
		];
		const out = await filterFalsePositives(input, deps);

		// Nothing dropped.
		expect(out.findings).toHaveLength(3);
		// Only the matched finding is demoted.
		expect(out.findings[0]!.confidence).toBe("firm");
		expect(out.findings[0]!.fp_filtered).toBe(true);
		expect(String(out.findings[0]!.validation_note)).toContain("Auto-demoted");
		expect(out.findings[1]!.confidence).toBe("firm");
		expect(out.findings[1]!.fp_filtered).toBeUndefined();
		expect(out.demotions).toHaveLength(1);
		expect(out.demotions[0]).toMatchObject({ findingId: "a", kind: "fingerprint", from: "confirmed", to: "firm" });
	});
});

describe("filterFalsePositives: fuzzy near-miss (precision-biased)", () => {
	const deps = (near: FpMemoryNearHit[]): FpFilterDeps => ({
		scope: SCOPE,
		calibration: CAL,
		async findByFingerprint() {
			return null;
		},
		async nearest() {
			return near;
		},
	});

	it("demotes a CONFIDENT fuzzy match (similarity >= greyHigh)", async () => {
		const out = await filterFalsePositives(
			[candidate("a", "fp-new", "firm", [1, 0])],
			deps([{ fingerprint: "fp-old", decision: "false_positive", distance: 0.1 }]),
		);
		expect(out.findings[0]!.confidence).toBe("tentative");
		expect(out.demotions[0]).toMatchObject({ kind: "fuzzy" });
	});

	it("does NOT demote a weak fuzzy match (below the confident band)", async () => {
		const out = await filterFalsePositives(
			[candidate("a", "fp-new", "firm", [1, 0])],
			deps([{ fingerprint: "fp-old", decision: "false_positive", distance: 0.9 }]),
		);
		expect(out.findings[0]!.confidence).toBe("firm");
		expect(out.demotions).toHaveLength(0);
	});
});

describe("filterFalsePositives: guardrails", () => {
	it("fails OPEN on a lookup error (finding retained, not demoted)", async () => {
		const deps: FpFilterDeps = {
			scope: SCOPE,
			calibration: CAL,
			async findByFingerprint() {
				throw new Error("store unavailable");
			},
		};
		const out = await filterFalsePositives([candidate("a", "fp-1", "confirmed")], deps);
		expect(out.findings).toHaveLength(1);
		expect(out.findings[0]!.confidence).toBe("confirmed");
		expect(out.demotions).toHaveLength(0);
	});
});

describe("demoteConfidence ladder", () => {
	it("drops one rung, floored at tentative; unknown -> tentative", () => {
		expect(demoteConfidence("confirmed")).toBe("firm");
		expect(demoteConfidence("firm")).toBe("tentative");
		expect(demoteConfidence("tentative")).toBe("tentative");
		expect(demoteConfidence("unverified")).toBe("tentative");
		expect(demoteConfidence(undefined)).toBe("tentative");
	});
});
