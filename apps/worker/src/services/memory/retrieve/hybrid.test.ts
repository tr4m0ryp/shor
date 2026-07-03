// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	accumulateRrf,
	DEFAULT_RRF_K,
	fuseTier,
	globalToCandidate,
	localToCandidate,
	recallGlobal,
	recallLocal,
	rrf,
	sortByScore,
} from "./hybrid.js";
import type {
	GlobalTierMatch,
	GlobalTierPort,
	LocalTierMatch,
	LocalTierPort,
} from "./types.js";

function local(id: string, distance: number, over: Partial<LocalTierMatch> = {}): LocalTierMatch {
	return {
		id,
		distance,
		cwe: null,
		vulnClass: null,
		severity: null,
		route: null,
		source: null,
		sink: null,
		componentVer: null,
		confidence: null,
		...over,
	};
}

describe("RRF math", () => {
	it("ranks an item that both rankings agree on first", () => {
		const fused = rrf([
			["a", "b"],
			["a", "c"],
		]);
		expect(fused[0]).toBe("a"); // rank-1 in both
		expect(fused).toContain("b");
		expect(fused).toContain("c");
	});

	it("uses k=60 by default and 1-based rank", () => {
		const scores = new Map<string, number>();
		accumulateRrf(scores, ["x", "y"], DEFAULT_RRF_K);
		expect(scores.get("x")).toBeCloseTo(1 / 61, 10);
		expect(scores.get("y")).toBeCloseTo(1 / 62, 10);
	});

	it("weights a ranking's contribution", () => {
		const scores = new Map<string, number>();
		accumulateRrf(scores, ["x"], DEFAULT_RRF_K, 2);
		expect(scores.get("x")).toBeCloseTo(2 / 61, 10);
	});

	it("sortByScore orders by descending score", () => {
		const scores = new Map([
			["low", 0.1],
			["high", 0.9],
			["mid", 0.5],
		]);
		expect(sortByScore(scores)).toEqual(["high", "mid", "low"]);
	});
});

describe("candidate mapping", () => {
	it("namespaces the local key and copies structured columns", () => {
		const c = localToCandidate(local("1", 0.2, { cwe: "CWE-89", route: "/x" }));
		expect(c.key).toBe("local:1");
		expect(c.tier).toBe("local");
		expect(c.cwe).toBe("CWE-89");
		expect(c.route).toBe("/x");
		expect(c.text).toBeNull();
	});

	it("projects a global payload onto the candidate shape", () => {
		const m: GlobalTierMatch = {
			id: "g1",
			distance: 0.3,
			kind: "exemplar",
			payload: { cwe: "CWE-79", vuln_class: "XSS", route: "/p", summary: "stored xss" },
		};
		const c = globalToCandidate(m);
		expect(c.key).toBe("global:g1");
		expect(c.cwe).toBe("CWE-79");
		expect(c.vulnClass).toBe("XSS");
		expect(c.text).toBe("stored xss");
	});
});

describe("recall + fuseTier", () => {
	const matches = [
		local("1", 0.1, { cwe: "CWE-89", sink: "db.query" }),
		local("2", 0.2, { cwe: "CWE-79", sink: "innerHTML" }),
	];
	const localPort: LocalTierPort = {
		async nearest() {
			return matches;
		},
	};

	it("recallLocal queries vec_text and vec_code when both vectors are present", async () => {
		const columns: string[] = [];
		const port: LocalTierPort = {
			async nearest(_s, _v, opts) {
				columns.push(opts?.column ?? "vec_text");
				return matches;
			},
		};
		const recall = await recallLocal(port, { tenantId: "t" }, [1, 0], [0, 1]);
		expect(columns).toEqual(["vec_text", "vec_code"]);
		expect(recall.denseRankings).toHaveLength(2);
		expect(recall.candidates.size).toBe(2);
	});

	it("fuseTier ranks the BM25/dense-agreed candidate first", async () => {
		const recall = await recallLocal(localPort, { tenantId: "t" }, [1, 0], null);
		const ranked = fuseTier(recall, ["cwe-89", "db.query"]);
		expect(ranked[0]?.id).toBe("1"); // dense rank-0 AND the only BM25 hit
	});

	it("recallGlobal maps global hits through the payload projection", async () => {
		const gm: GlobalTierMatch[] = [
			{ id: "g", distance: 0.1, kind: "finding", payload: { cwe: "CWE-22" } },
		];
		const port: GlobalTierPort = {
			async nearest() {
				return gm;
			},
		};
		const recall = await recallGlobal(port, [1, 0], null);
		expect([...recall.candidates.values()][0]?.cwe).toBe("CWE-22");
	});
});
