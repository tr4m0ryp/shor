// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * False-positive AUTO-FILTER (spec T6, R8; valid-vuln-yield focus).
 *
 * A finding that matches a project's remembered false positive (`fp_memory`)
 * is DEMOTED — its confidence drops one rung and it is flagged — but NEVER
 * dropped. FP filtering costs recall (Sifting-the-Noise missed 77-85% of some
 * CWE classes), so the recall-safe move is to lower confidence, keep the row,
 * and let a human overrule. Two match modes:
 *   - EXACT: the candidate's stable `fingerprint` is already in `fp_memory`
 *     for this project (deterministic — always demote).
 *   - FUZZY: an embedding near-miss of a remembered FP. Biased to precision —
 *     only the CONFIDENT band (>= greyHigh) demotes, so a genuinely new bug
 *     that merely resembles an old FP is never silently suppressed.
 *
 * The repositories (apps/web `fpMemoryRepo`) are injected as ports; this module
 * is pure over them, so tests pass fakes.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { FindingConfidence } from "../../../job/findings/types.js";
import type { FindingLike } from "../schema/index.js";
import { defaultDedupCalibration } from "./calibrate.js";
import { distanceToSimilarity } from "./cluster.js";
import type { CalibratedThreshold, DedupCandidate, Vector } from "./types.js";

/** Tenant/project scope for the `fp_memory` lookup (RLS claim source). */
export interface FpScope {
	readonly tenantId: string;
	readonly projectId: string;
}

/** A remembered false positive (subset of the `fp_memory` row). */
export interface FpMemoryHit {
	readonly fingerprint: string;
	readonly reason?: string | null;
	readonly decision?: string | null;
}

/** A fuzzy `fp_memory` near-miss: a hit plus its pgvector cosine distance. */
export interface FpMemoryNearHit extends FpMemoryHit {
	readonly distance: number;
}

/** Injected `fp_memory` reader ports (real `fpMemoryRepo` satisfies these). */
export interface FpFilterDeps {
	readonly scope: FpScope;
	/** Exact fingerprint lookup — the deterministic fast path. */
	findByFingerprint(
		scope: FpScope,
		fingerprint: string,
	): Promise<FpMemoryHit | null>;
	/** Optional fuzzy semantic lookup for near-miss variants. */
	nearest?(scope: FpScope, vec: Vector, limit: number): Promise<FpMemoryNearHit[]>;
	/** Calibrated band; defaults to the 017 sweep. */
	readonly calibration?: CalibratedThreshold;
	/** Max fuzzy neighbours to inspect. Default 8. */
	readonly fuzzyLimit?: number;
	readonly logger?: ActivityLogger | undefined;
}

/** How a demotion was triggered. */
export type FpMatchKind = "fingerprint" | "fuzzy";

/** One applied demotion, for the audit trail. */
export interface FpDemotion {
	readonly findingId: string;
	readonly kind: FpMatchKind;
	readonly from: string;
	readonly to: FindingConfidence;
	readonly matchedFingerprint: string;
	readonly similarity?: number;
	readonly decision: string;
}

/** Result: the full finding set (nothing dropped) + the demotions applied. */
export interface FpFilterResult {
	readonly findings: FindingLike[];
	readonly demotions: FpDemotion[];
}

/**
 * Demotion ladder — one rung down, floored at `tentative`. `unverified` is
 * reserved (out-of-scope routing), so a demotion never lands there.
 */
const LADDER: readonly FindingConfidence[] = ["confirmed", "firm", "tentative"];

/** Lower a confidence one rung (floored at `tentative`). */
export function demoteConfidence(current: unknown): FindingConfidence {
	const c = typeof current === "string" ? current : "";
	const idx = LADDER.indexOf(c as FindingConfidence);
	if (idx < 0) return "tentative";
	return LADDER[Math.min(idx + 1, LADDER.length - 1)] as FindingConfidence;
}

/** Return a demoted COPY of `finding` (never mutates; never drops). */
function applyDemotion(
	finding: FindingLike,
	hit: FpMemoryHit,
	kind: FpMatchKind,
): FindingLike {
	const from = typeof finding.confidence === "string" ? finding.confidence : "firm";
	const to = demoteConfidence(from);
	const noteBase =
		typeof finding.validation_note === "string" ? finding.validation_note : "";
	const decision = hit.decision ?? "false_positive";
	const suffix = `Auto-demoted: matches a remembered ${decision} (${kind}).`;
	return {
		...finding,
		confidence: to,
		fp_filtered: true,
		fp_memory_decision: decision,
		...(hit.reason ? { fp_memory_reason: hit.reason } : {}),
		validation_note: noteBase ? `${noteBase} ${suffix}` : suffix,
	};
}

/**
 * Demote every candidate that matches this project's `fp_memory`. Returns the
 * SAME set (input order, nothing removed) with matched findings demoted, plus
 * the list of demotions. Exact-fingerprint hits always demote; fuzzy hits only
 * demote in the confident band (precision-biased). Lookup failures fail OPEN
 * (no demotion) so a flaky store never suppresses a finding.
 */
export async function filterFalsePositives(
	candidates: readonly DedupCandidate[],
	deps: FpFilterDeps,
): Promise<FpFilterResult> {
	const calibration = deps.calibration ?? defaultDedupCalibration();
	const fuzzyLimit = deps.fuzzyLimit ?? 8;
	const findings: FindingLike[] = [];
	const demotions: FpDemotion[] = [];

	for (const cand of candidates) {
		const finding = cand.finding;
		const fingerprint =
			typeof finding.fingerprint === "string" ? finding.fingerprint : "";
		const from =
			typeof finding.confidence === "string" ? finding.confidence : "firm";
		const findingId = typeof finding.id === "string" ? finding.id : fingerprint;

		// EXACT fast path.
		let hit: FpMemoryHit | null = null;
		if (fingerprint) {
			try {
				hit = await deps.findByFingerprint(deps.scope, fingerprint);
			} catch (err) {
				deps.logger?.warn?.("fp-filter: exact lookup failed (fail-open)", {
					error: err instanceof Error ? err.message : String(err),
				});
			}
		}
		if (hit) {
			const demoted = applyDemotion(finding, hit, "fingerprint");
			findings.push(demoted);
			demotions.push({
				findingId,
				kind: "fingerprint",
				from,
				to: demoted.confidence as FindingConfidence,
				matchedFingerprint: hit.fingerprint,
				decision: hit.decision ?? "false_positive",
			});
			continue;
		}

		// FUZZY path — confident band only.
		const near = await fuzzyMatch(cand, deps, fuzzyLimit, calibration);
		if (near) {
			const demoted = applyDemotion(finding, near.hit, "fuzzy");
			findings.push(demoted);
			demotions.push({
				findingId,
				kind: "fuzzy",
				from,
				to: demoted.confidence as FindingConfidence,
				matchedFingerprint: near.hit.fingerprint,
				similarity: near.similarity,
				decision: near.hit.decision ?? "false_positive",
			});
			continue;
		}

		findings.push(finding);
	}

	if (demotions.length > 0) {
		deps.logger?.info?.("fp-filter: demoted findings matching fp_memory", {
			demoted: demotions.length,
			total: candidates.length,
		});
	}
	return { findings, demotions };
}

/** Best fuzzy `fp_memory` match in the confident band, or null. */
async function fuzzyMatch(
	cand: DedupCandidate,
	deps: FpFilterDeps,
	limit: number,
	calibration: CalibratedThreshold,
): Promise<{ hit: FpMemoryHit; similarity: number } | null> {
	if (!deps.nearest || !cand.vecText) return null;
	let hits: FpMemoryNearHit[];
	try {
		hits = await deps.nearest(deps.scope, cand.vecText, limit);
	} catch (err) {
		deps.logger?.warn?.("fp-filter: fuzzy lookup failed (fail-open)", {
			error: err instanceof Error ? err.message : String(err),
		});
		return null;
	}
	let best: { hit: FpMemoryHit; similarity: number } | null = null;
	for (const h of hits) {
		const similarity = distanceToSimilarity(h.distance);
		if (similarity >= calibration.greyHigh && (!best || similarity > best.similarity)) {
			best = { hit: h, similarity };
		}
	}
	return best;
}
