// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-tier hybrid recall (spec T4): dense HNSW (via the injected `nearest`
 * ports) on `vec_text` and, when a code vector is present, `vec_code`, fused
 * with the in-worker BM25 sparse channel by Reciprocal Rank Fusion (RRF, k=60).
 *
 * RRF is rank-based, so it fuses the dense cosine scale and the BM25 lexical
 * scale without normalizing either — the reason the design fuses on rank, not
 * score. Each tier independently recalls its top 20-30, then the cross-tier
 * weighting + rerank happen in `fuse.ts`.
 */

import { bm25Rank, toLexicalDoc } from "./bm25.js";
import type {
	ExemplarCandidate,
	GlobalKind,
	GlobalTierMatch,
	GlobalTierPort,
	LocalTierMatch,
	LocalTierPort,
	RetrievalScope,
} from "./types.js";

/** RRF constant (spec T4). */
export const DEFAULT_RRF_K = 60;
/** Per-tier hybrid recall depth (spec: 20-30). */
export const DEFAULT_RECALL = 24;

/**
 * Add one ranking's reciprocal-rank contributions into `scores`, optionally
 * weighted (the cross-tier "local > global" knob lives in fuse.ts). Rank is
 * 1-based: `weight / (k + rank)`.
 */
export function accumulateRrf(
	scores: Map<string, number>,
	ranking: readonly string[],
	k: number,
	weight = 1,
): void {
	ranking.forEach((key, idx) => {
		scores.set(key, (scores.get(key) ?? 0) + weight / (k + idx + 1));
	});
}

/** Keys sorted by descending fused score (V8 Array.sort is stable on ties). */
export function sortByScore(scores: Map<string, number>): string[] {
	return [...scores.entries()].sort((a, b) => b[1] - a[1]).map(([key]) => key);
}

/** Fuse several rankings by unweighted RRF, returning keys best-first. */
export function rrf(
	rankings: readonly (readonly string[])[],
	k: number = DEFAULT_RRF_K,
): string[] {
	const scores = new Map<string, number>();
	for (const ranking of rankings) accumulateRrf(scores, ranking, k);
	return sortByScore(scores);
}

/** First non-empty string in `payload` among candidate keys, else null. */
function pickStr(
	payload: Record<string, unknown>,
	keys: readonly string[],
): string | null {
	for (const key of keys) {
		const v = payload[key];
		if (typeof v === "string" && v.trim() !== "") return v.trim();
	}
	return null;
}

/** Narrow the repo's free-form `kind` string to a known {@link GlobalKind}. */
function coerceKind(kind: string): GlobalKind | null {
	return kind === "abstraction" || kind === "exemplar" || kind === "finding"
		? kind
		: null;
}

/** Map a local-tier hit onto the shared candidate shape (never seeded). */
export function localToCandidate(m: LocalTierMatch): ExemplarCandidate {
	return {
		key: `local:${m.id}`,
		tier: "local",
		id: m.id,
		distance: m.distance,
		cwe: m.cwe,
		vulnClass: m.vulnClass,
		severity: m.severity,
		route: m.route,
		source: m.source,
		sink: m.sink,
		componentVer: m.componentVer,
		confidence: m.confidence,
		text: null,
		kind: null,
		seeded: false,
	};
}

/**
 * Project a global-tier hit's JSONB payload onto the shared candidate shape.
 * A global exemplar (or a payload flagged `seeded`) is a SEEDED known-pattern
 * technique — flagged here so the guardrail can down-weight/cap it downstream.
 */
export function globalToCandidate(m: GlobalTierMatch): ExemplarCandidate {
	const p = m.payload ?? {};
	const kind = coerceKind(m.kind);
	const seeded = kind === "exemplar" || p.seeded === true;
	return {
		key: `global:${m.id}`,
		tier: "global",
		id: m.id,
		distance: m.distance,
		cwe: pickStr(p, ["cwe"]),
		vulnClass: pickStr(p, ["vuln_class", "vulnClass", "class", "category"]),
		severity: pickStr(p, ["severity"]),
		route: pickStr(p, ["route", "endpoint", "path"]),
		source: pickStr(p, ["source", "taint_source"]),
		sink: pickStr(p, ["sink", "taint_sink"]),
		componentVer: pickStr(p, ["component_ver", "componentVer", "component"]),
		confidence: pickStr(p, ["confidence"]),
		text: pickStr(p, ["text", "doc", "summary", "abstraction"]),
		kind,
		seeded,
	};
}

/** The identifier fields BM25 tokenizes for one candidate. */
function lexicalFields(c: ExemplarCandidate): (string | null)[] {
	return [c.cwe, c.vulnClass, c.severity, c.route, c.source, c.sink, c.componentVer, c.text];
}

/** Candidates + one dense ranking (ordered keys) per queried dense column. */
export interface TierRecall {
	readonly candidates: Map<string, ExemplarCandidate>;
	readonly denseRankings: string[][];
}

/**
 * Merge a dense channel's hits into the running candidate map (keeping the
 * nearer distance on a repeat) and return its ordered key ranking.
 */
function mergeChannel(
	candidates: Map<string, ExemplarCandidate>,
	hits: readonly ExemplarCandidate[],
): string[] {
	const ranking: string[] = [];
	for (const hit of hits) {
		const prior = candidates.get(hit.key);
		if (!prior) candidates.set(hit.key, hit);
		else if (hit.distance < prior.distance) candidates.set(hit.key, hit);
		ranking.push(hit.key);
	}
	return ranking;
}

/** Recall the local tier over vec_text (+ vec_code when present). */
export async function recallLocal(
	port: LocalTierPort,
	scope: RetrievalScope,
	vecText: readonly number[] | null,
	vecCode: readonly number[] | null,
	opts: { recall?: number; cwe?: string | null } = {},
): Promise<TierRecall> {
	const limit = opts.recall ?? DEFAULT_RECALL;
	const candidates = new Map<string, ExemplarCandidate>();
	const denseRankings: string[][] = [];
	if (vecText) {
		const hits = await port.nearest(scope, vecText, {
			column: "vec_text",
			limit,
			cwe: opts.cwe ?? null,
		});
		denseRankings.push(mergeChannel(candidates, hits.map(localToCandidate)));
	}
	if (vecCode) {
		const hits = await port.nearest(scope, vecCode, { column: "vec_code", limit });
		denseRankings.push(mergeChannel(candidates, hits.map(localToCandidate)));
	}
	return { candidates, denseRankings };
}

/** Recall the global (cross-tenant) tier over vec_text (+ vec_code). */
export async function recallGlobal(
	port: GlobalTierPort,
	vecText: readonly number[] | null,
	vecCode: readonly number[] | null,
	opts: { recall?: number } = {},
): Promise<TierRecall> {
	const limit = opts.recall ?? DEFAULT_RECALL;
	const candidates = new Map<string, ExemplarCandidate>();
	const denseRankings: string[][] = [];
	if (vecText) {
		const hits = await port.nearest(vecText, { column: "vec_text", limit });
		denseRankings.push(mergeChannel(candidates, hits.map(globalToCandidate)));
	}
	if (vecCode) {
		const hits = await port.nearest(vecCode, { column: "vec_code", limit });
		denseRankings.push(mergeChannel(candidates, hits.map(globalToCandidate)));
	}
	return { candidates, denseRankings };
}

/**
 * Fuse one tier's dense rankings with its BM25 lexical ranking by RRF, returning
 * the tier's candidates ranked best-first (capped at the recall depth). The
 * BM25 half ranks the recalled candidates on their identifier columns.
 */
export function fuseTier(
	recall: TierRecall,
	queryTerms: readonly string[],
	opts: { k?: number; recall?: number } = {},
): ExemplarCandidate[] {
	const k = opts.k ?? DEFAULT_RRF_K;
	const cap = opts.recall ?? DEFAULT_RECALL;
	const docs = [...recall.candidates.values()].map((c) =>
		toLexicalDoc(c.key, lexicalFields(c)),
	);
	const lexical = bm25Rank(queryTerms, docs);
	const fusedKeys = rrf([...recall.denseRankings, lexical], k);
	const out: ExemplarCandidate[] = [];
	for (const key of fusedKeys) {
		const candidate = recall.candidates.get(key);
		if (candidate) out.push(candidate);
		if (out.length >= cap) break;
	}
	return out;
}
