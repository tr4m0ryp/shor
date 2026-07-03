// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Embedding-recall clustering with a STRUCTURAL GATE and grey-band adjudication
 * (spec T6, R10).
 *
 * Two findings link only when (1) they share a structural anchor (the gate,
 * `fingerprint.structuralAgree`) AND (2) their embedding similarity clears the
 * calibrated boundary — or, inside the grey band, an LLM adjudicator confirms
 * the shared root cause. Clusters are formed by COMPLETE LINKAGE: a group's
 * WEAKEST internal pair must clear the bar, so A~B and B~C never drag in an
 * unrelated A~C (the connected-components chaining that hides real bugs).
 *
 * Pure over injected inputs (vectors + an adjudicator) — no DB, no network.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { structuralAgree, structuralKeyOf } from "./fingerprint.js";
import type {
	AdjudicateFn,
	CalibratedThreshold,
	DedupCandidate,
	Vector,
} from "./types.js";

function clamp01(n: number): number {
	if (!Number.isFinite(n)) return 0;
	return n < 0 ? 0 : n > 1 ? 1 : n;
}

/**
 * Cosine similarity of two dense vectors, clamped to [0,1] (a negative cosine
 * is "unrelated", not "anti-related", for dedup). Returns 0 for a zero vector.
 */
export function cosineSimilarity(a: Vector, b: Vector): number {
	const len = Math.min(a.length, b.length);
	let dot = 0;
	let na = 0;
	let nb = 0;
	for (let i = 0; i < len; i++) {
		const x = a[i] as number;
		const y = b[i] as number;
		dot += x * y;
		na += x * x;
		nb += y * y;
	}
	if (na === 0 || nb === 0) return 0;
	return clamp01(dot / (Math.sqrt(na) * Math.sqrt(nb)));
}

/** pgvector cosine DISTANCE (`<=>`, 0..2) -> similarity in [0,1]. */
export function distanceToSimilarity(distance: number | null | undefined): number {
	if (distance === null || distance === undefined || !Number.isFinite(distance))
		return 0;
	return clamp01(1 - distance);
}

/**
 * COMPLETE-LINKAGE agglomerative clustering over a pairwise `score` matrix.
 * Repeatedly merges the two clusters whose WEAKEST cross-pair score is highest,
 * while that weakest link still clears `threshold`. Because the weakest link
 * gates every merge, each returned cluster is a clique above `threshold` — no
 * single-link chaining. Deterministic: stable index order, first-found ties.
 * Returns index groups (each a sorted list); every index appears exactly once.
 */
export function completeLinkageClusters(
	n: number,
	score: readonly (readonly number[])[],
	threshold: number,
): number[][] {
	let clusters: number[][] = [];
	for (let i = 0; i < n; i++) clusters.push([i]);

	for (;;) {
		let bestA = -1;
		let bestB = -1;
		let bestLink = -Infinity;
		for (let a = 0; a < clusters.length; a++) {
			for (let b = a + 1; b < clusters.length; b++) {
				const ca = clusters[a] as number[];
				const cb = clusters[b] as number[];
				let weakest = Infinity;
				for (const i of ca) {
					for (const j of cb) {
						const s = (score[i] as readonly number[])[j] as number;
						if (s < weakest) weakest = s;
					}
				}
				if (weakest >= threshold && weakest > bestLink) {
					bestLink = weakest;
					bestA = a;
					bestB = b;
				}
			}
		}
		if (bestA < 0) break;
		const merged = [
			...(clusters[bestA] as number[]),
			...(clusters[bestB] as number[]),
		].sort((x, y) => x - y);
		clusters = clusters.filter((_, idx) => idx !== bestA && idx !== bestB);
		clusters.push(merged);
	}

	return clusters.map((c) => [...c].sort((x, y) => x - y));
}

/** Injected collaborators for {@link clusterCandidates}. */
export interface SemanticClusterDeps {
	readonly calibration: CalibratedThreshold;
	/** Grey-band adjudicator; never throws (fail open to "distinct"). */
	readonly adjudicate: AdjudicateFn;
	readonly logger?: ActivityLogger | undefined;
}

/**
 * Build the pairwise link-score matrix, applying the structural gate and
 * grey-band adjudication. A gate-mismatch pair scores 0 (never links). Above
 * `greyHigh` the raw similarity is used; inside the band the adjudicator decides
 * (confirmed -> lifted to `threshold` so it links; refuted -> 0). The diagonal
 * is 1. Adjudications are counted for the caller's log.
 */
async function buildLinkScores(
	candidates: readonly DedupCandidate[],
	deps: SemanticClusterDeps,
): Promise<{ score: number[][]; adjudicated: number }> {
	const n = candidates.length;
	const keys = candidates.map((c) => structuralKeyOf(c.finding));
	const score: number[][] = Array.from({ length: n }, () =>
		new Array<number>(n).fill(0),
	);
	const { greyHigh, greyLow, threshold } = deps.calibration;
	let adjudicated = 0;

	for (let i = 0; i < n; i++) {
		score[i]![i] = 1;
		const vi = candidates[i]!.vecText;
		for (let j = i + 1; j < n; j++) {
			const vj = candidates[j]!.vecText;
			if (!vi || !vj || !structuralAgree(keys[i]!, keys[j]!)) continue;
			const sim = cosineSimilarity(vi, vj);
			let s = 0;
			if (sim >= greyHigh) s = sim;
			else if (sim > greyLow) {
				adjudicated += 1;
				const same = await deps.adjudicate(
					candidates[i]!.finding,
					candidates[j]!.finding,
				);
				s = same ? Math.max(sim, threshold) : 0;
			}
			score[i]![j] = s;
			score[j]![i] = s;
		}
	}
	return { score, adjudicated };
}

/**
 * Cluster candidates by root cause: structural gate + calibrated similarity +
 * grey-band adjudication, grouped by complete linkage. Returns index groups
 * (each finding appears once); singletons are their own group. Candidates
 * without a vector can only be singletons here — the fingerprint fast-path (in
 * `index.ts`) is what merges vector-less exact rediscoveries.
 */
export async function clusterCandidates(
	candidates: readonly DedupCandidate[],
	deps: SemanticClusterDeps,
): Promise<number[][]> {
	const n = candidates.length;
	if (n <= 1) return n === 1 ? [[0]] : [];
	const { score, adjudicated } = await buildLinkScores(candidates, deps);
	const clusters = completeLinkageClusters(n, score, deps.calibration.threshold);
	deps.logger?.info?.("dedup: semantic clustering complete", {
		candidates: n,
		clusters: clusters.length,
		greyBandAdjudications: adjudicated,
		threshold: deps.calibration.threshold,
	});
	return clusters;
}
