// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	applyGuardrail,
	DEFAULT_SEED_WEIGHT,
	type GuardrailConfig,
	readGuardrailConfig,
} from "./guardrail.js";
import type { ExemplarCandidate, RagExemplar } from "./types.js";

// ── fakes ──────────────────────────────────────────────────────────────────

function cand(
	key: string,
	over: Partial<ExemplarCandidate> = {},
): ExemplarCandidate {
	const tier = over.tier ?? (key.startsWith("global") ? "global" : "local");
	return {
		key,
		tier,
		id: key,
		distance: 0.1,
		cwe: null,
		vulnClass: null,
		severity: null,
		route: null,
		source: null,
		sink: null,
		componentVer: null,
		confidence: null,
		text: null,
		kind: tier === "global" ? "finding" : null,
		seeded: false,
		...over,
	};
}

/** A ranked exemplar: `seed*` keys are seeded exemplars, others non-seeded. */
function ex(
	key: string,
	score: number,
	over: Partial<ExemplarCandidate> = {},
): RagExemplar {
	const seeded = over.seeded ?? key.startsWith("seed");
	const tier: "local" | "global" = over.tier ?? (seeded ? "global" : "local");
	const kind = seeded ? "exemplar" : (over.kind ?? (tier === "global" ? "finding" : null));
	const candidate = cand(key, { ...over, tier, seeded, kind });
	return { candidate, score, line: `- ${key}` };
}

const CFG = (over: Partial<GuardrailConfig> = {}): GuardrailConfig => ({
	seedWeight: DEFAULT_SEED_WEIGHT,
	seedMax: 3,
	...over,
});

function seededCount(list: readonly RagExemplar[]): number {
	return list.filter((e) => e.candidate.seeded).length;
}

// ── config: env overrides + clamping ────────────────────────────────────────

describe("readGuardrailConfig", () => {
	it("defaults: seedWeight 0.7, seedMax floor(topK/2)", () => {
		expect(readGuardrailConfig(6, {})).toEqual({ seedWeight: 0.7, seedMax: 3 });
		expect(readGuardrailConfig(5, {})).toEqual({ seedWeight: 0.7, seedMax: 2 });
		expect(readGuardrailConfig(8, {})).toEqual({ seedWeight: 0.7, seedMax: 4 });
	});

	it("respects env overrides", () => {
		const cfg = readGuardrailConfig(6, {
			SHOR_RAG_SEED_WEIGHT: "0.5",
			SHOR_RAG_SEED_MAX: "2",
		});
		expect(cfg).toEqual({ seedWeight: 0.5, seedMax: 2 });
	});

	it("clamps seedWeight into [0, 1]", () => {
		expect(readGuardrailConfig(6, { SHOR_RAG_SEED_WEIGHT: "5" }).seedWeight).toBe(1);
		expect(readGuardrailConfig(6, { SHOR_RAG_SEED_WEIGHT: "-3" }).seedWeight).toBe(0);
		// non-numeric -> default
		expect(readGuardrailConfig(6, { SHOR_RAG_SEED_WEIGHT: "abc" }).seedWeight).toBe(0.7);
	});

	it("clamps seedMax into [0, topK]", () => {
		expect(readGuardrailConfig(6, { SHOR_RAG_SEED_MAX: "99" }).seedMax).toBe(6);
		expect(readGuardrailConfig(6, { SHOR_RAG_SEED_MAX: "-1" }).seedMax).toBe(0);
		expect(readGuardrailConfig(6, { SHOR_RAG_SEED_MAX: "2" }).seedMax).toBe(2);
	});
});

// ── regression guard: zero seeds -> identical output ────────────────────────

describe("applyGuardrail — zero seeds (backward compatible)", () => {
	it("returns ranked.slice(0, topK), unchanged", () => {
		const ranked = [ex("l1", 3), ex("l2", 2), ex("g1", 1), ex("l3", 0.5)];
		const out = applyGuardrail(ranked, 3, CFG());
		expect(out).toEqual(ranked.slice(0, 3));
		// same object identities — no re-wrapping / re-scoring happened.
		expect(out[0]).toBe(ranked[0]);
		expect(out[2]).toBe(ranked[2]);
	});

	it("shorter-than-topK lists pass through untouched", () => {
		const ranked = [ex("l1", 2), ex("l2", 1)];
		expect(applyGuardrail(ranked, 6, CFG())).toEqual(ranked);
	});
});

// ── (a) novelty down-weight ─────────────────────────────────────────────────

describe("applyGuardrail — novelty down-weight", () => {
	it("a real finding outranks an equally-scored seed", () => {
		const finding = ex("l1", 1); // non-seeded, score 1
		const seed = ex("seed1", 1, { vulnClass: "SQLi" }); // seeded, score 1
		const out = applyGuardrail([seed, finding], 6, CFG());
		expect(out[0]?.candidate.key).toBe("l1"); // 1.0 > 0.7*1
		expect(out[0]?.candidate.seeded).toBe(false);
	});

	it("a strongly-similar seed still leads a weak finding", () => {
		const seed = ex("seed1", 2, { vulnClass: "SQLi" }); // 0.7*2 = 1.4
		const finding = ex("l1", 1);
		const out = applyGuardrail([seed, finding], 6, CFG());
		expect(out[0]?.candidate.key).toBe("seed1");
	});
});

// ── (b) seed cap + backfill ─────────────────────────────────────────────────

describe("applyGuardrail — seed cap", () => {
	it("caps seeds at seedMax and backfills non-seeds to stay full", () => {
		const ranked = [
			ex("seed1", 2, { vulnClass: "A" }),
			ex("seed2", 2, { vulnClass: "B" }),
			ex("seed3", 2, { vulnClass: "C" }),
			ex("seed4", 2, { vulnClass: "D" }),
			ex("seed5", 2, { vulnClass: "E" }),
			ex("l1", 1),
			ex("l2", 1),
			ex("l3", 1),
			ex("l4", 1),
			ex("l5", 1),
		];
		const out = applyGuardrail(ranked, 6, CFG({ seedMax: 3 }));
		expect(out).toHaveLength(6); // list stays full
		expect(seededCount(out)).toBe(3); // capped at seedMax
	});

	it("seedMax=0 removes all seeds, keeping only real findings", () => {
		const ranked = [ex("seed1", 2, { vulnClass: "A" }), ex("l1", 1), ex("l2", 1)];
		const out = applyGuardrail(ranked, 6, CFG({ seedMax: 0 }));
		expect(seededCount(out)).toBe(0);
		expect(out.map((e) => e.candidate.key)).toEqual(["l1", "l2"]);
	});
});

// ── (c) diversity (MMR-lite) ────────────────────────────────────────────────

describe("applyGuardrail — diversity", () => {
	it("collapses near-duplicate seeds sharing a technique to one", () => {
		const ranked = [
			ex("seed1", 3, { vulnClass: "SQLi" }),
			ex("seed2", 2.9, { vulnClass: "SQLi" }), // near-dup technique
			ex("seed3", 2.8, { vulnClass: "XSS" }),
			ex("l1", 1),
			ex("l2", 1),
		];
		const out = applyGuardrail(ranked, 6, CFG({ seedMax: 3 }));
		const seeds = out.filter((e) => e.candidate.seeded).map((e) => e.candidate.key);
		expect(seeds).toContain("seed1");
		expect(seeds).toContain("seed3");
		expect(seeds).not.toContain("seed2"); // suppressed near-duplicate
	});

	it("collapses seeds sharing a CWE when technique is absent", () => {
		const ranked = [
			ex("seed1", 3, { cwe: "CWE-89" }),
			ex("seed2", 2.9, { cwe: "CWE-89" }),
			ex("l1", 1),
		];
		const out = applyGuardrail(ranked, 6, CFG({ seedMax: 3 }));
		expect(seededCount(out)).toBe(1);
	});

	it("keeps idea-less seeds distinct (no over-suppression)", () => {
		const ranked = [ex("seed1", 3), ex("seed2", 2.9), ex("l1", 1)];
		const out = applyGuardrail(ranked, 6, CFG({ seedMax: 3 }));
		expect(seededCount(out)).toBe(2);
	});
});
