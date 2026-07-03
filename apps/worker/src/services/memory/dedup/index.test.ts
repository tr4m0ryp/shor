// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-scan dedup orchestrator (spec T6). Under test:
 *  - the fpv1 fast-path merges same-scan exact dups WITHOUT any embedding;
 *  - a prior-scan fingerprint hit labels the finding `rediscovered` and folds
 *    it into the prior cluster;
 *  - a confident, structurally-gated recall hit also `rediscovered`s;
 *  - disabled -> identity (every candidate `novel`); nothing is ever dropped.
 */

import { describe, expect, it, vi } from "vitest";
import {
	dedupFindings,
	readDedupXScanEnabled,
	structuralKeyOf,
} from "./index.js";
import type {
	CalibratedThreshold,
	DedupCandidate,
	PriorFinding,
} from "./types.js";

const CAL: CalibratedThreshold = {
	threshold: 0.5,
	greyLow: 0.4,
	greyHigh: 0.6,
	f1: 1,
	precision: 1,
	recall: 1,
	beta: 0.5,
};

const noAdjudicate = vi.fn(async () => false);

function exactPair(): DedupCandidate[] {
	// Same file/CWE/category/sink/code -> same fpv1, different id + line. No vectors.
	const shared = {
		cwe: "CWE-639",
		category: "authz",
		sink: "db.Users.Find",
		code_snippet: "var u = db.Users.Find(id); return Ok(u);",
	};
	return [
		{ finding: { ...shared, id: "a", vulnerable_code_location: { file: "U.cs", line: 10 } } },
		{ finding: { ...shared, id: "b", vulnerable_code_location: { file: "U.cs", line: 88 } } },
	];
}

describe("dedupFindings: fingerprint fast-path", () => {
	it("merges same-scan exact dups without embeddings", async () => {
		const { verdicts, findings } = await dedupFindings(exactPair(), {
			adjudicate: noAdjudicate,
			calibration: CAL,
			enabled: true,
		});
		expect(findings).toHaveLength(2);
		expect(verdicts[0]!.fpv1).toBe(verdicts[1]!.fpv1);
		expect(findings[0]!.cluster_id).toBe(findings[1]!.cluster_id);
		expect(verdicts[0]!.alsoReportedAs).toContain("b");
		expect(verdicts[1]!.alsoReportedAs).toContain("a");
		expect(verdicts.map((v) => v.novelty)).toEqual(["novel", "novel"]);
		expect(noAdjudicate).not.toHaveBeenCalled();
	});
});

describe("dedupFindings: cross-scan rediscovery", () => {
	const candidate: DedupCandidate = {
		finding: { id: "c", cwe: "CWE-1", category: "authz", vulnerable_code_location: { file: "dir/U.cs", line: 3 } },
		vecText: [1, 0],
	};

	it("labels a prior fingerprint hit as rediscovered, folding into its cluster", async () => {
		const prior: PriorFinding = {
			id: "prior-1",
			clusterId: "cl_prior",
			structural: structuralKeyOf(candidate.finding),
		};
		const { verdicts, findings } = await dedupFindings([candidate], {
			adjudicate: noAdjudicate,
			calibration: CAL,
			lookupFingerprint: async () => prior,
			enabled: true,
		});
		expect(verdicts[0]!.novelty).toBe("rediscovered");
		expect(verdicts[0]!.clusterId).toBe("cl_prior");
		expect(verdicts[0]!.mergedInto).toBe("prior-1");
		expect(verdicts[0]!.matchKind).toBe("fingerprint");
		expect(findings[0]!.cluster_id).toBe("cl_prior");
	});

	it("rediscovers via a confident, structurally-gated recall hit", async () => {
		const prior: PriorFinding = {
			id: "prior-2",
			clusterId: "cl_recall",
			distance: 0.1, // -> similarity 0.9 >= greyHigh
			structural: structuralKeyOf(candidate.finding),
		};
		const { verdicts } = await dedupFindings([candidate], {
			adjudicate: noAdjudicate,
			calibration: CAL,
			recall: async () => [prior],
			enabled: true,
		});
		expect(verdicts[0]!.novelty).toBe("rediscovered");
		expect(verdicts[0]!.clusterId).toBe("cl_recall");
		expect(verdicts[0]!.matchKind).toBe("cluster");
		expect(verdicts[0]!.similarity).toBeCloseTo(0.9, 6);
	});

	it("stays novel when a recall hit fails the structural gate", async () => {
		const prior: PriorFinding = {
			id: "prior-3",
			clusterId: "cl_x",
			distance: 0.0, // similarity 1.0, but unrelated structure
			structural: structuralKeyOf({ cwe: "CWE-79", category: "xss", vulnerable_code_location: { file: "web/Other.tsx", line: 1 } }),
		};
		const { verdicts } = await dedupFindings([candidate], {
			adjudicate: noAdjudicate,
			calibration: CAL,
			recall: async () => [prior],
			enabled: true,
		});
		expect(verdicts[0]!.novelty).toBe("novel");
	});
});

describe("dedupFindings: flag gate", () => {
	it("disabled -> identity: every candidate novel, matchKind none", async () => {
		const { verdicts, findings } = await dedupFindings(exactPair(), {
			adjudicate: noAdjudicate,
			enabled: false,
		});
		expect(verdicts.every((v) => v.novelty === "novel")).toBe(true);
		expect(verdicts.every((v) => v.matchKind === "none")).toBe(true);
		expect(findings).toHaveLength(2);
		expect(findings.every((f) => typeof f.cluster_id === "string")).toBe(true);
	});

	it("reads SHOR_DEDUP_XSCAN", () => {
		expect(readDedupXScanEnabled({ SHOR_DEDUP_XSCAN: "1" })).toBe(true);
		expect(readDedupXScanEnabled({ SHOR_DEDUP_XSCAN: "off" })).toBe(false);
		expect(readDedupXScanEnabled({})).toBe(false);
	});
});
