// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it, vi } from "vitest";
import { applyPromptContext } from "../../prompt-manager/prompt-context.js";
import type { EmbedClient, RerankHit } from "../embed/index.js";
import {
	clampLocalWeight,
	clampTopK,
	renderInclude,
	weightedCrossTierRrf,
} from "./fuse.js";
import {
	buildQueryTerms,
	readMemoryRetrieveEnabled,
	retrieveExemplars,
} from "./index.js";
import type {
	ExemplarCandidate,
	GlobalTierMatch,
	GlobalTierPort,
	LocalTierMatch,
	LocalTierPort,
	RetrieveDeps,
} from "./types.js";

// ── fakes ──────────────────────────────────────────────────────────────────

function embedResult() {
	return { model: "m", dim: 2, embeddings: [[1, 0]], tokenCounts: [2] };
}

function makeEmbed(over: Partial<EmbedClient> = {}): EmbedClient {
	return {
		enabled: true,
		embedText: async () => embedResult(),
		embedCode: async () => embedResult(),
		rerank: async () => [] as RerankHit[],
		...over,
	};
}

function localMatch(id: string, over: Partial<LocalTierMatch> = {}): LocalTierMatch {
	return {
		id,
		distance: 0.1,
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

function localPortReturning(matches: LocalTierMatch[]): LocalTierPort & { calls: number } {
	return {
		calls: 0,
		async nearest() {
			this.calls++;
			return matches;
		},
	};
}

function globalPortReturning(
	matches: GlobalTierMatch[],
): GlobalTierPort & { calls: number } {
	return {
		calls: 0,
		async nearest() {
			this.calls++;
			return matches;
		},
	};
}

function candidate(key: string, tier: "local" | "global"): ExemplarCandidate {
	return {
		key,
		tier,
		id: key,
		distance: 0.1,
		cwe: "CWE-89",
		vulnClass: "SQLi",
		severity: "high",
		route: "/login",
		source: "req.body",
		sink: "db.query",
		componentVer: null,
		confidence: null,
		text: null,
	};
}

// ── env flag ─────────────────────────────────────────────────────────────────

describe("readMemoryRetrieveEnabled", () => {
	it("is off unless SHOR_MEMORY_RETRIEVE is truthy", () => {
		expect(readMemoryRetrieveEnabled({})).toBe(false);
		expect(readMemoryRetrieveEnabled({ SHOR_MEMORY_RETRIEVE: "false" })).toBe(false);
		expect(readMemoryRetrieveEnabled({ SHOR_MEMORY_RETRIEVE: "1" })).toBe(true);
		expect(readMemoryRetrieveEnabled({ SHOR_MEMORY_RETRIEVE: "TRUE" })).toBe(true);
	});
});

// ── weighted cross-tier fusion ──────────────────────────────────────────────

describe("weightedCrossTierRrf", () => {
	it("favours a local exemplar over an equally-ranked global one", () => {
		const fused = weightedCrossTierRrf(
			[candidate("local:a", "local")],
			[candidate("global:b", "global")],
		);
		expect(fused[0]?.candidate.tier).toBe("local");
		expect(fused[0]?.score).toBeGreaterThan(fused[1]?.score ?? 0);
	});

	it("clamps the local weight into [1.3, 1.5]", () => {
		expect(clampLocalWeight(undefined)).toBeCloseTo(1.4, 5);
		expect(clampLocalWeight(5)).toBe(1.5);
		expect(clampLocalWeight(1)).toBe(1.3);
	});

	it("clamps topK into [5, 8]", () => {
		expect(clampTopK(undefined)).toBe(6);
		expect(clampTopK(2)).toBe(5);
		expect(clampTopK(99)).toBe(8);
	});
});

// ── render ──────────────────────────────────────────────────────────────────

describe("renderInclude", () => {
	it("returns null for an empty list", () => {
		expect(renderInclude([])).toBeNull();
	});

	it("renders a header plus one bullet per exemplar", () => {
		const out = renderInclude([
			{ candidate: candidate("local:a", "local"), score: 1, line: "- line-a" },
			{ candidate: candidate("global:b", "global"), score: 0.5, line: "- line-b" },
		]);
		expect(out).toContain("past-vulnerability exemplars");
		expect(out).toContain("- line-a");
		expect(out).toContain("- line-b");
	});
});

describe("buildQueryTerms", () => {
	it("tokenizes the text, cwe, and extra identifier terms", () => {
		const terms = buildQueryTerms({ text: "sql injection", cwe: "CWE-89", terms: ["db.query"] });
		expect(terms).toContain("sql");
		expect(terms).toContain("cwe-89");
		expect(terms).toContain("db.query");
	});
});

// ── orchestrator ────────────────────────────────────────────────────────────

const SCOPE = { tenantId: "t", projectId: "p" };
const QUERY = { text: "sql injection at /login" };

function deps(over: Partial<RetrieveDeps> = {}): RetrieveDeps {
	return {
		embed: makeEmbed(),
		local: localPortReturning([]),
		global: globalPortReturning([]),
		enabled: true,
		...over,
	};
}

describe("retrieveExemplars — gating", () => {
	it("returns nothing and calls no port when the flag is off", async () => {
		const local = localPortReturning([localMatch("1")]);
		const global = globalPortReturning([]);
		const res = await retrieveExemplars(QUERY, SCOPE, deps({ local, global, enabled: false }));
		expect(res).toEqual({ exemplars: [], rendered: null });
		expect(local.calls).toBe(0);
		expect(global.calls).toBe(0);
	});

	it("returns nothing when the embed client is disabled", async () => {
		const res = await retrieveExemplars(
			QUERY,
			SCOPE,
			deps({ embed: makeEmbed({ enabled: false }) }),
		);
		expect(res.rendered).toBeNull();
	});

	it("empty store -> empty include (prompt unchanged)", async () => {
		const res = await retrieveExemplars(QUERY, SCOPE, deps());
		expect(res.exemplars).toHaveLength(0);
		expect(res.rendered).toBeNull();
	});
});

describe("retrieveExemplars — retrieval", () => {
	it("always queries BOTH tiers and renders a local-favoured include", async () => {
		const local = localPortReturning([
			localMatch("l1", { cwe: "CWE-89", route: "/login", source: "req.body", sink: "db.query" }),
		]);
		const global = globalPortReturning([
			{ id: "g1", distance: 0.1, kind: "exemplar", payload: { cwe: "CWE-89", route: "/login" } },
		]);
		const res = await retrieveExemplars(QUERY, SCOPE, deps({ local, global }));
		expect(local.calls).toBeGreaterThan(0);
		expect(global.calls).toBeGreaterThan(0);
		expect(res.exemplars[0]?.candidate.tier).toBe("local");
		expect(res.rendered).toContain("tier: local");
	});

	it("reranks: the cross-encoder order overrides the RRF order", async () => {
		const local = localPortReturning([localMatch("l1")]);
		const global = globalPortReturning([
			{ id: "g1", distance: 0.1, kind: "exemplar", payload: { cwe: "CWE-89" } },
		]);
		// shortlist = [local:l1, global:g1]; pick index 1 (the global one) first.
		const embed = makeEmbed({ rerank: async () => [{ index: 1, score: 9 }] });
		const res = await retrieveExemplars(QUERY, SCOPE, deps({ local, global, embed }));
		expect(res.exemplars).toHaveLength(1);
		expect(res.exemplars[0]?.candidate.tier).toBe("global");
	});

	it("fails open to the RRF order when rerank throws", async () => {
		const local = localPortReturning([localMatch("l1"), localMatch("l2")]);
		const embed = makeEmbed({
			rerank: async () => {
				throw new Error("reranker down");
			},
		});
		const res = await retrieveExemplars(QUERY, SCOPE, deps({ local, embed }));
		expect(res.exemplars.length).toBeGreaterThan(0);
		expect(res.exemplars[0]?.candidate.tier).toBe("local");
	});

	it("clamps the final exemplar count into [5, 8]", async () => {
		const many = Array.from({ length: 10 }, (_, i) => localMatch(`l${i}`));
		const local = localPortReturning(many);
		const small = await retrieveExemplars(QUERY, SCOPE, deps({ local, config: { topK: 2 } }));
		expect(small.exemplars).toHaveLength(5);
		const big = await retrieveExemplars(QUERY, SCOPE, deps({ local, config: { topK: 20 } }));
		expect(big.exemplars).toHaveLength(8);
	});

	it("fails open (returns empty) when a port throws", async () => {
		const local: LocalTierPort = {
			async nearest() {
				throw new Error("db down");
			},
		};
		const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const res = await retrieveExemplars(QUERY, SCOPE, deps({ local, logger }));
		expect(res.rendered).toBeNull();
		expect(logger.error).toHaveBeenCalled();
	});
});

// ── prompt include integration ──────────────────────────────────────────────

describe("{{RAG_EXEMPLARS}} include", () => {
	it("substitutes the rendered exemplars", () => {
		expect(applyPromptContext("[{{RAG_EXEMPLARS}}]", { ragExemplars: "- ex" })).toBe(
			"[- ex]",
		);
	});

	it("renders the neutral sentinel when absent (prompt unchanged)", () => {
		expect(applyPromptContext("[{{RAG_EXEMPLARS}}]")).toBe("[(none)]");
	});
});
