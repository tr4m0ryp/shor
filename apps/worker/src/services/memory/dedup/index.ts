// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cross-scan dedup / novelty — public surface + orchestrator (spec T6, R10).
 *
 * The cross-scan extension of the per-scan `services/dedup-judge`. Pipeline:
 *   1. `fpv1` fingerprint fast-path — exact same-scan dups and prior-scan
 *      rediscoveries merge WITHOUT an embedding.
 *   2. embedding recall + complete-linkage + structural gate + grey-band
 *      adjudication (`cluster.ts`) merges same-scan near-dups.
 *   3. cross-scan attach — a cluster folds into a prior finding's cluster on a
 *      fingerprint hit or a confident, structurally-gated recall match.
 * Output: per-candidate `novel` / `rediscovered` verdicts + findings stamped
 * with a stable `cluster_id` and `also_reported_as`. Nothing is dropped.
 *
 * Flag-gated / default-OFF: `SHOR_DEDUP_XSCAN`. Disabled -> identity (every
 * candidate `novel`, no LLM, no DB), so a stock scan is byte-for-byte unchanged.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { FindingLike } from "../schema/index.js";
import { defaultDedupCalibration } from "./calibrate.js";
import { clusterCandidates, distanceToSimilarity } from "./cluster.js";
import {
	computeFpv1,
	structuralAgree,
	structuralKeyOf,
} from "./fingerprint.js";
import type {
	AdjudicateFn,
	CalibratedThreshold,
	DedupCandidate,
	DedupVerdict,
	NoveltyLabel,
	PriorFinding,
	RecallFn,
} from "./types.js";

export * from "./types.js";
export {
	codeRegionHash,
	computeFpv1,
	structuralAgree,
	structuralKeyOf,
} from "./fingerprint.js";
export {
	clusterCandidates,
	completeLinkageClusters,
	cosineSimilarity,
	distanceToSimilarity,
	type SemanticClusterDeps,
} from "./cluster.js";
export {
	defaultDedupCalibration,
	featureSimilarity,
	seedSamples,
	sweepThreshold,
	type SweepOptions,
	type SweepSample,
} from "./calibrate.js";
export {
	demoteConfidence,
	filterFalsePositives,
	type FpDemotion,
	type FpFilterDeps,
	type FpFilterResult,
	type FpMatchKind,
	type FpMemoryHit,
	type FpMemoryNearHit,
	type FpScope,
} from "./fp-filter.js";

/** Cross-scan fingerprint lookup port (prior-scan `fpv1` -> its cluster). */
export type LookupFingerprintFn = (
	fpv1: string,
) => Promise<PriorFinding | null>;

/** Injected collaborators for {@link dedupFindings}. */
export interface DedupDeps {
	/** Grey-band adjudicator (same-scan near-dups). Fail-open to "distinct". */
	readonly adjudicate: AdjudicateFn;
	/** Cross-scan ANN recall (finding_embedding.nearest wrapper). Optional. */
	readonly recall?: RecallFn;
	/** Cross-scan exact fingerprint lookup. Optional. */
	readonly lookupFingerprint?: LookupFingerprintFn;
	/** Calibrated boundary; defaults to the 017 F1-sweep. */
	readonly calibration?: CalibratedThreshold;
	readonly logger?: ActivityLogger | undefined;
	/** Override the `SHOR_DEDUP_XSCAN` env gate (mainly for tests). */
	readonly enabled?: boolean | undefined;
}

/** Result: per-candidate verdicts + findings stamped with cluster identity. */
export interface DedupResult {
	readonly verdicts: DedupVerdict[];
	readonly findings: FindingLike[];
}

/** True when `SHOR_DEDUP_XSCAN` is truthy. */
export function readDedupXScanEnabled(
	env: NodeJS.ProcessEnv = process.env,
): boolean {
	const raw = env["SHOR_DEDUP_XSCAN"]?.trim().toLowerCase();
	return raw === "1" || raw === "true" || raw === "yes" || raw === "on";
}

/** A tiny union-find over candidate indices (same-scan cluster assembly). */
class UnionFind {
	private readonly parent: number[];
	constructor(n: number) {
		this.parent = Array.from({ length: n }, (_, i) => i);
	}
	find(x: number): number {
		let r = x;
		while (this.parent[r] !== r) r = this.parent[r] as number;
		let c = x;
		while (this.parent[c] !== c) {
			const next = this.parent[c] as number;
			this.parent[c] = r;
			c = next;
		}
		return r;
	}
	union(a: number, b: number): void {
		const ra = this.find(a);
		const rb = this.find(b);
		if (ra !== rb) this.parent[Math.max(ra, rb)] = Math.min(ra, rb);
	}
}

function idOf(finding: FindingLike): string {
	if (typeof finding.id === "string" && finding.id) return finding.id;
	if (typeof finding.fingerprint === "string" && finding.fingerprint)
		return finding.fingerprint;
	return "";
}

/** Assemble same-scan clusters: union exact-fpv1 dups + semantic cliques. */
function assembleClusters(
	fpv1s: readonly string[],
	semantic: readonly (readonly number[])[],
	n: number,
): number[][] {
	const uf = new UnionFind(n);
	const byFpv1 = new Map<string, number>();
	for (let i = 0; i < n; i++) {
		const seen = byFpv1.get(fpv1s[i] as string);
		if (seen === undefined) byFpv1.set(fpv1s[i] as string, i);
		else uf.union(seen, i);
	}
	for (const group of semantic) {
		for (let k = 1; k < group.length; k++) uf.union(group[0] as number, group[k] as number);
	}
	const groups = new Map<number, number[]>();
	for (let i = 0; i < n; i++) {
		const root = uf.find(i);
		const g = groups.get(root) ?? [];
		g.push(i);
		groups.set(root, g);
	}
	return [...groups.values()].map((g) => g.sort((a, b) => a - b));
}

/** Best confident, structurally-gated cross-scan prior for a candidate. */
async function crossScanMatch(
	rep: DedupCandidate,
	repKey: ReturnType<typeof structuralKeyOf>,
	deps: DedupDeps,
	cal: CalibratedThreshold,
): Promise<{ prior: PriorFinding; kind: "fingerprint" | "cluster"; similarity?: number } | null> {
	// Fingerprint fast-path first (no embedding needed).
	if (deps.lookupFingerprint) {
		const prior = await deps.lookupFingerprint(computeFpv1(rep.finding));
		if (prior) return { prior, kind: "fingerprint" };
	}
	if (!deps.recall) return null;
	const priors = await deps.recall(rep);
	let best: { prior: PriorFinding; similarity: number } | null = null;
	for (const p of priors) {
		const similarity = distanceToSimilarity(p.distance);
		if (
			similarity >= cal.greyHigh &&
			structuralAgree(repKey, p.structural) &&
			(!best || similarity > best.similarity)
		) {
			best = { prior: p, similarity };
		}
	}
	return best ? { prior: best.prior, kind: "cluster", similarity: best.similarity } : null;
}

function identityResult(candidates: readonly DedupCandidate[]): DedupResult {
	const verdicts: DedupVerdict[] = [];
	const findings: FindingLike[] = [];
	for (const c of candidates) {
		const fpv1 = computeFpv1(c.finding);
		const clusterId = `cl_${fpv1.slice(5, 17)}`;
		verdicts.push({
			findingId: idOf(c.finding),
			fpv1,
			novelty: "novel",
			clusterId,
			alsoReportedAs: [],
			matchKind: "none",
			reason: "dedup disabled",
		});
		findings.push({ ...c.finding, cluster_id: clusterId });
	}
	return { verdicts, findings };
}

/**
 * Run the cross-scan dedup pipeline over a batch of candidate findings.
 * Deterministic and order-stable; never drops a finding. When disabled, returns
 * the identity result (every candidate `novel`).
 */
export async function dedupFindings(
	candidates: readonly DedupCandidate[],
	deps: DedupDeps,
): Promise<DedupResult> {
	const enabled = deps.enabled ?? readDedupXScanEnabled();
	if (!enabled || candidates.length === 0) return identityResult(candidates);

	const cal = deps.calibration ?? defaultDedupCalibration();
	const n = candidates.length;
	const fpv1s = candidates.map((c) => computeFpv1(c.finding));
	const keys = candidates.map((c) => structuralKeyOf(c.finding));

	const semantic = await clusterCandidates(candidates, {
		calibration: cal,
		adjudicate: deps.adjudicate,
		logger: deps.logger,
	});
	const clusters = assembleClusters(fpv1s, semantic, n);

	const verdicts: DedupVerdict[] = new Array(n);
	const stamped: FindingLike[] = new Array(n);

	for (const group of clusters) {
		const repIdx = group[0] as number;
		const rep = candidates[repIdx] as DedupCandidate;
		const memberIds = group.map((i) => idOf((candidates[i] as DedupCandidate).finding));
		const cross = await crossScanMatch(rep, keys[repIdx]!, deps, cal);

		let novelty: NoveltyLabel = cross ? "rediscovered" : "novel";
		const clusterId = cross?.prior.clusterId ?? `cl_${fpv1s[repIdx]!.slice(5, 17)}`;
		const reason = cross
			? `cross-scan ${cross.kind} match to ${cross.prior.id}`
			: group.length > 1
				? "same-scan cluster; no prior match"
				: "no prior or sibling match";

		for (const i of group) {
			const alsoReportedAs = memberIds.filter((_, k) => group[k] !== i);
			verdicts[i] = {
				findingId: idOf((candidates[i] as DedupCandidate).finding),
				fpv1: fpv1s[i] as string,
				novelty,
				clusterId,
				...(cross ? { mergedInto: cross.prior.id } : {}),
				alsoReportedAs,
				matchKind: cross ? cross.kind : group.length > 1 ? "cluster" : "none",
				...(cross?.similarity !== undefined ? { similarity: cross.similarity } : {}),
				reason,
			};
			stamped[i] = {
				...(candidates[i] as DedupCandidate).finding,
				cluster_id: clusterId,
				...(alsoReportedAs.length > 0 ? { also_reported_as: alsoReportedAs } : {}),
			};
		}
	}

	deps.logger?.info?.("dedup: cross-scan pass complete", {
		candidates: n,
		clusters: clusters.length,
		rediscovered: verdicts.filter((v) => v.novelty === "rediscovered").length,
	});
	return { verdicts, findings: stamped };
}
