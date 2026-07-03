// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-tier fusion + rerank + render (spec T4).
 *
 * Takes each tier's hybrid-fused candidate list and:
 *   1. fuses them by WEIGHTED RRF — the local tier's contributions are scaled
 *      up (1.3-1.5x, default 1.4) so a project-local exemplar outranks an
 *      equally-ranked global one ("local > global" knob);
 *   2. reranks the fused shortlist with the bge cross-encoder (002's client,
 *      input capped ~50) — what makes cross-source candidates competable;
 *   3. renders the top 5-8 into `{{RAG_EXEMPLARS}}` bullet lines.
 *
 * Fail-open: a disabled/failing reranker degrades to the weighted-RRF order (the
 * exemplars are still useful) — retrieval never throws away recall on a rerank
 * hiccup.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { MAX_RERANK } from "../embed/index.js";
import type { EmbedClient } from "../embed/index.js";
import { accumulateRrf, DEFAULT_RRF_K, sortByScore } from "./hybrid.js";
import type { ExemplarCandidate, RagExemplar } from "./types.js";

/** Spec: local 1.3-1.5x global. */
const LOCAL_WEIGHT_MIN = 1.3;
const LOCAL_WEIGHT_MAX = 1.5;
const DEFAULT_LOCAL_WEIGHT = 1.4;
/** Spec: 5-8 exemplars to DeepSeek. */
const TOPK_MIN = 5;
const TOPK_MAX = 8;
const DEFAULT_TOPK = 6;

const NA = "n/a";
const MAX_TEXT = 160;

/** Clamp the cross-tier local weight into the spec band [1.3, 1.5]. */
export function clampLocalWeight(w: number | undefined): number {
	const v = w ?? DEFAULT_LOCAL_WEIGHT;
	if (!Number.isFinite(v)) return DEFAULT_LOCAL_WEIGHT;
	return Math.min(LOCAL_WEIGHT_MAX, Math.max(LOCAL_WEIGHT_MIN, v));
}

/** Clamp the final exemplar count into the spec band [5, 8]. */
export function clampTopK(k: number | undefined): number {
	const v = k ?? DEFAULT_TOPK;
	if (!Number.isFinite(v)) return DEFAULT_TOPK;
	return Math.min(TOPK_MAX, Math.max(TOPK_MIN, Math.trunc(v)));
}

/** A candidate paired with its fused (pre-rerank) RRF score. */
export interface FusedCandidate {
	readonly candidate: ExemplarCandidate;
	readonly score: number;
}

/**
 * Weighted cross-tier RRF: local contributions are scaled by `localWeight`,
 * global by 1. Candidate keys are already tier-namespaced, so the two lists
 * never collide. Returns candidates ordered best-first with their fused score.
 */
export function weightedCrossTierRrf(
	local: readonly ExemplarCandidate[],
	global: readonly ExemplarCandidate[],
	opts: { localWeight?: number; k?: number } = {},
): FusedCandidate[] {
	const weight = clampLocalWeight(opts.localWeight);
	const k = opts.k ?? DEFAULT_RRF_K;
	const byKey = new Map<string, ExemplarCandidate>();
	for (const c of [...local, ...global]) byKey.set(c.key, c);

	const scores = new Map<string, number>();
	accumulateRrf(scores, local.map((c) => c.key), k, weight);
	accumulateRrf(scores, global.map((c) => c.key), k, 1);

	const out: FusedCandidate[] = [];
	for (const key of sortByScore(scores)) {
		const candidate = byKey.get(key);
		if (candidate) out.push({ candidate, score: scores.get(key) ?? 0 });
	}
	return out;
}

function truncate(s: string, max: number): string {
	const t = s.replace(/\s+/g, " ").trim();
	return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
}

/**
 * Render one exemplar as a prompt bullet — a compact, non-secret abstraction of
 * a past vulnerability (identifier columns only; the store never persisted raw
 * doc text for the local tier). Mirrors the verbalizer's metadata prefix style.
 */
export function renderExemplarLine(c: ExemplarCandidate): string {
	const prefix =
		`[CWE=${c.cwe ?? NA} | class=${c.vulnClass ?? NA} | ` +
		`severity=${c.severity ?? NA} | route=${c.route ?? NA}]`;
	const flow = `${c.source ?? NA} -> ${c.sink ?? NA}`;
	const tags = [`tier: ${c.tier}`];
	if (c.componentVer) tags.push(c.componentVer);
	if (c.confidence) tags.push(`confidence: ${c.confidence}`);
	let line = `- ${prefix} ${flow} (${tags.join("; ")})`;
	if (c.text) line += `\n  ${truncate(c.text, MAX_TEXT)}`;
	return line;
}

/** The passage a candidate is reranked on (richer than the render line). */
function rerankPassage(c: ExemplarCandidate): string {
	const parts = [
		c.cwe && `CWE ${c.cwe}`,
		c.vulnClass,
		c.severity && `severity ${c.severity}`,
		c.route && `route ${c.route}`,
		(c.source || c.sink) && `${c.source ?? NA} to ${c.sink ?? NA}`,
		c.componentVer,
		c.text,
	].filter((p): p is string => typeof p === "string" && p.length > 0);
	return parts.join(" | ") || "(no descriptor)";
}

function toExemplar(fc: FusedCandidate, score: number): RagExemplar {
	return { candidate: fc.candidate, score, line: renderExemplarLine(fc.candidate) };
}

/**
 * Rerank the weighted-RRF shortlist with the cross-encoder and return the top
 * `topK` exemplars. Falls back to the RRF order when the reranker is disabled,
 * returns nothing, or throws.
 */
export async function fuseAndRerank(
	local: readonly ExemplarCandidate[],
	global: readonly ExemplarCandidate[],
	deps: {
		embed: EmbedClient;
		queryText: string;
		localWeight?: number;
		k?: number;
		topK?: number;
		logger?: ActivityLogger | undefined;
	},
): Promise<RagExemplar[]> {
	const topK = clampTopK(deps.topK);
	const fused = weightedCrossTierRrf(local, global, {
		...(deps.localWeight !== undefined && { localWeight: deps.localWeight }),
		...(deps.k !== undefined && { k: deps.k }),
	});
	if (fused.length === 0) return [];

	const shortlist = fused.slice(0, MAX_RERANK);
	if (deps.embed.enabled) {
		try {
			const passages = shortlist.map((fc) => rerankPassage(fc.candidate));
			const hits = await deps.embed.rerank(deps.queryText, passages, { topK });
			if (hits.length > 0) {
				return hits
					.map((h) => {
						const fc = shortlist[h.index];
						return fc ? toExemplar(fc, h.score) : null;
					})
					.filter((e): e is RagExemplar => e !== null)
					.slice(0, topK);
			}
		} catch (err) {
			deps.logger?.warn("rag-retrieve: rerank failed, using RRF order", {
				reason: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return shortlist.slice(0, topK).map((fc) => toExemplar(fc, fc.score));
}

/**
 * Render the ranked exemplars into the `{{RAG_EXEMPLARS}}` block, or `null` when
 * empty (the caller then leaves the include unset -> "(none)" sentinel).
 */
export function renderInclude(exemplars: readonly RagExemplar[]): string | null {
	if (exemplars.length === 0) return null;
	const header =
		"Relevant past-vulnerability exemplars (most similar first) — use as " +
		"hypotheses to check, not confirmed findings:";
	return [header, ...exemplars.map((e) => e.line)].join("\n");
}
