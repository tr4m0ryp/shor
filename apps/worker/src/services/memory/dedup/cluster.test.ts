// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Embedding clustering (spec T6). Under test:
 *  - complete linkage AVOIDS connected-components chaining (A~B, B~C but not
 *    A~C never collapses into one cluster);
 *  - the structural gate blocks a merge across unrelated file+CWE even at
 *    cosine 1.0;
 *  - a grey-band pair routes to the LLM adjudicator, which decides the merge.
 */

import { describe, expect, it, vi } from "vitest";
import {
	clusterCandidates,
	completeLinkageClusters,
	cosineSimilarity,
	distanceToSimilarity,
} from "./cluster.js";
import type { CalibratedThreshold, DedupCandidate } from "./types.js";

const CAL: CalibratedThreshold = {
	threshold: 0.5,
	greyLow: 0.4,
	greyHigh: 0.6,
	f1: 1,
	precision: 1,
	recall: 1,
	beta: 0.5,
};

describe("completeLinkageClusters: no chaining", () => {
	it("does NOT chain A~B, B~C into one cluster when A~C is weak", () => {
		const score = [
			[1, 0.9, 0.1],
			[0.9, 1, 0.9],
			[0.1, 0.9, 1],
		];
		const clusters = completeLinkageClusters(3, score, 0.5);
		expect(clusters).toHaveLength(2);
		expect(clusters.some((c) => c.length === 3)).toBe(false);
		expect(clusters).toContainEqual([0, 1]);
		expect(clusters).toContainEqual([2]);
	});

	it("merges a genuine clique (all pairs above threshold)", () => {
		const score = [
			[1, 0.8, 0.7],
			[0.8, 1, 0.9],
			[0.7, 0.9, 1],
		];
		expect(completeLinkageClusters(3, score, 0.5)).toEqual([[0, 1, 2]]);
	});
});

describe("cosine + distance helpers", () => {
	it("cosineSimilarity clamps a negative cosine to 0", () => {
		expect(cosineSimilarity([1, 0], [-1, 0])).toBe(0);
		expect(cosineSimilarity([1, 0], [1, 0])).toBe(1);
	});
	it("distanceToSimilarity maps pgvector cosine distance to [0,1]", () => {
		expect(distanceToSimilarity(0)).toBe(1);
		expect(distanceToSimilarity(0.2)).toBeCloseTo(0.8, 6);
		expect(distanceToSimilarity(null)).toBe(0);
	});
});

function cand(
	id: string,
	file: string,
	cwe: string,
	category: string,
	vecText: number[],
): DedupCandidate {
	return {
		finding: { id, cwe, category, vulnerable_code_location: { file, line: 1 } },
		vecText,
	};
}

describe("clusterCandidates: structural gate + adjudication", () => {
	it("merges near-dups sharing a file even with different CWE labels", async () => {
		const adjudicate = vi.fn(async () => true);
		const clusters = await clusterCandidates(
			[
				cand("a", "x/UsersController.cs", "CWE-639", "authz", [1, 0]),
				cand("b", "x/UsersController.cs", "CWE-862", "authz", [1, 0]),
			],
			{ calibration: CAL, adjudicate },
		);
		expect(clusters).toEqual([[0, 1]]);
		// cosine 1.0 is above the grey band — no LLM call needed.
		expect(adjudicate).not.toHaveBeenCalled();
	});

	it("BLOCKS a merge across unrelated file+CWE even at cosine 1.0", async () => {
		const adjudicate = vi.fn(async () => true);
		const clusters = await clusterCandidates(
			[
				cand("a", "svc/EffectService.cs", "CWE-918", "ssrf", [1, 0]),
				cand("b", "web/MarkdownRenderer.tsx", "CWE-79", "xss", [1, 0]),
			],
			{ calibration: CAL, adjudicate },
		);
		expect(clusters).toHaveLength(2);
		expect(adjudicate).not.toHaveBeenCalled();
	});

	it("routes a grey-band pair to the adjudicator and merges on YES", async () => {
		const adjudicate = vi.fn(async () => true);
		const grey = Math.sqrt(3) / 2; // [0.5, grey] . [1,0] = cosine 0.5 (in band)
		const clusters = await clusterCandidates(
			[
				cand("a", "A.cs", "CWE-1", "authz", [1, 0]),
				cand("b", "A.cs", "CWE-2", "authz", [0.5, grey]),
			],
			{ calibration: CAL, adjudicate },
		);
		expect(adjudicate).toHaveBeenCalledTimes(1);
		expect(clusters).toEqual([[0, 1]]);
	});

	it("keeps a grey-band pair separate on a NO adjudication", async () => {
		const adjudicate = vi.fn(async () => false);
		const grey = Math.sqrt(3) / 2;
		const clusters = await clusterCandidates(
			[
				cand("a", "A.cs", "CWE-1", "authz", [1, 0]),
				cand("b", "A.cs", "CWE-2", "authz", [0.5, grey]),
			],
			{ calibration: CAL, adjudicate },
		);
		expect(adjudicate).toHaveBeenCalledTimes(1);
		expect(clusters).toHaveLength(2);
	});
});
