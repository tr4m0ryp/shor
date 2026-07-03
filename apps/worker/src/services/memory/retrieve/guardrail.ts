// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Novelty / diversity guardrail for the two-tier RAG shortlist.
 *
 * Seeded known-pattern technique exemplars (`global_pool` rows with
 * `kind:'exemplar'` / `payload.seeded`) are useful hypotheses but must NOT
 * dominate the top-k and crowd out exploration of real per-project findings.
 * Applied to the fused/reranked shortlist in `fuse.ts`, this stage:
 *
 *   a. NOVELTY DOWN-WEIGHT — scale each seeded candidate's score by
 *      `SHOR_RAG_SEED_WEIGHT` (default 0.7) so an equally-similar real finding
 *      outranks a seeded technique (seeds inform, findings lead);
 *   b. SEED CAP — keep at most `SHOR_RAG_SEED_MAX` (default floor(topK/2))
 *      seeded exemplars, backfilling the vacated slots from the non-seeded
 *      remainder so the final list stays full (5-8);
 *   c. DIVERSITY (MMR-lite) — among the kept seeds, suppress near-duplicates by
 *      technique/CWE so the seeds span distinct ideas, not N variants of one.
 *
 * BACKWARD-COMPATIBLE: when the shortlist carries ZERO seeded candidates the
 * output is `ranked.slice(0, topK)` — byte-identical to the pre-guardrail path.
 * Fail-open: this is pure ranking arithmetic and never throws away recall.
 */

import type { ExemplarCandidate, RagExemplar } from "./types.js";

const SEED_WEIGHT_ENV = "SHOR_RAG_SEED_WEIGHT";
const SEED_MAX_ENV = "SHOR_RAG_SEED_MAX";

/** Seeds inform, findings lead: down-weight seeded scores by this factor. */
export const DEFAULT_SEED_WEIGHT = 0.7;

/** Resolved, clamped guardrail knobs for one retrieval. */
export interface GuardrailConfig {
	/** Seeded-score multiplier, clamped to [0, 1]. */
	readonly seedWeight: number;
	/** Max seeded exemplars in the final top-k, clamped to [0, topK]. */
	readonly seedMax: number;
}

/** Clamp `v` into [lo, hi]. */
function clamp(v: number, lo: number, hi: number): number {
	return Math.min(hi, Math.max(lo, v));
}

/** Parse a finite float env override, else fall back. */
function parseFloatEnv(raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const v = Number.parseFloat(raw);
	return Number.isFinite(v) ? v : fallback;
}

/** Parse a finite integer env override, else fall back. */
function parseIntEnv(raw: string | undefined, fallback: number): number {
	if (raw === undefined || raw.trim() === "") return fallback;
	const v = Number.parseInt(raw, 10);
	return Number.isFinite(v) ? v : fallback;
}

/**
 * Read + clamp the guardrail knobs for a given `topK`. Defaults preserve
 * exploration: seeds are down-weighted (0.7) and capped at half the top-k.
 */
export function readGuardrailConfig(
	topK: number,
	env: NodeJS.ProcessEnv = process.env,
): GuardrailConfig {
	const seedWeight = clamp(parseFloatEnv(env[SEED_WEIGHT_ENV], DEFAULT_SEED_WEIGHT), 0, 1);
	const defaultMax = Math.floor(topK / 2);
	const seedMax = clamp(parseIntEnv(env[SEED_MAX_ENV], defaultMax), 0, topK);
	return { seedWeight, seedMax };
}

/**
 * Diversity signature: a seed's dominant idea. Prefer the vuln-class technique,
 * fall back to CWE, then to the unique key (so an idea-less seed is never
 * treated as a near-duplicate of another).
 */
function seedSignature(c: ExemplarCandidate): string {
	const vc = c.vulnClass?.trim().toLowerCase();
	if (vc) return `vc:${vc}`;
	const cwe = c.cwe?.trim().toLowerCase();
	if (cwe) return `cwe:${cwe}`;
	return `id:${c.key}`;
}

/** Re-wrap an exemplar with its down-weighted effective score. */
function withScore(e: RagExemplar, score: number): RagExemplar {
	return { candidate: e.candidate, score, line: e.line };
}

/** A candidate paired with its post-down-weight effective ranking score. */
interface Weighted {
	readonly exemplar: RagExemplar;
	readonly effective: number;
	readonly idx: number;
}

/**
 * Apply the novelty/diversity guardrail to the ranked shortlist and return the
 * final top-k. When there are no seeded candidates this is exactly
 * `ranked.slice(0, topK)` (regression guard).
 */
export function applyGuardrail(
	ranked: readonly RagExemplar[],
	topK: number,
	cfg: GuardrailConfig,
): RagExemplar[] {
	if (!ranked.some((e) => e.candidate.seeded)) return ranked.slice(0, topK);

	// (a) Novelty down-weight, then stable re-sort by effective score (original
	// rank breaks ties, so a same-score non-seed keeps its slot over a seed).
	const weighted: Weighted[] = ranked.map((e, idx) => {
		const effective = e.candidate.seeded ? e.score * cfg.seedWeight : e.score;
		const exemplar = e.candidate.seeded ? withScore(e, effective) : e;
		return { exemplar, effective, idx };
	});
	weighted.sort((a, b) => b.effective - a.effective || a.idx - b.idx);

	// (b)+(c) Walk best-first: keep every non-seed; admit a seed only if it is a
	// new idea (diversity) and under the cap. Dropped seeds are skipped, so their
	// slots backfill from the non-seeded remainder — the list stays full.
	const kept: RagExemplar[] = [];
	const seenSeeds = new Set<string>();
	let seedCount = 0;
	for (const w of weighted) {
		const c = w.exemplar.candidate;
		if (c.seeded) {
			const sig = seedSignature(c);
			if (seenSeeds.has(sig)) continue; // (c) near-duplicate technique/CWE
			if (seedCount >= cfg.seedMax) continue; // (b) cap
			seenSeeds.add(sig);
			seedCount++;
		}
		kept.push(w.exemplar);
		if (kept.length >= topK) break;
	}
	return kept;
}
