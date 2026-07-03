// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Regression scorecard (spec T15): four axes over ONE finding set graded against
 * the fixed benchmark — valid-vuln RECALL, false-positive RATE, dedup PRECISION,
 * and proof-confidence CALIBRATION. Run per release over the SAME benchmark (the
 * `benchmark_id` makes "same benchmark" checkable) so regressions are visible.
 *
 * Pure over injected inputs: it takes the grader's {@link GradeReport}, the graded
 * findings, and the benchmark, and returns a {@link Scorecard}. No IO, no clock —
 * `generated_at` is stamped by the writer in {@link ./index}. Cross-run history
 * lives in {@link ./regression}.
 */

import { computeCalibration } from "./calibration.js";
import type { CalibrationReport, CalibrationSample } from "./calibration.js";
import { confidenceToProb } from "./corpus.js";
import type {
	Benchmark,
	BenchmarkFinding,
	GradeReport,
	MatchKind,
} from "./types.js";

const NOTES: readonly string[] = [
	"recall = ground-truth vulns covered by >=1 finding / total ground-truth vulns.",
	"false_positive_rate = findings reproducing a known-FP label / total findings.",
	"precision = true-positive findings / (true-positive + false-positive findings); unmatched findings may be novel and are excluded from precision.",
	"dedup_precision = merged pairs (same cluster_id) whose two findings map to the SAME ground-truth vuln / (correct + incorrect) merges; pairs with an unmatched member are unlabeled and excluded.",
	"calibration bins predicted P(TP) vs observed TP fraction over labeled (TP/FP) findings; ECE/MCE/Brier summarize it.",
	"benchmark_id is a stable hash of the benchmark ids — compare scorecards across releases only when it matches.",
];

/** Valid-vuln recall over the benchmark. */
export interface RecallMetrics {
	readonly ground_truth: number;
	readonly covered: number;
	readonly recall: number | null;
	/** Ground-truth vuln ids no finding covered (the misses). */
	readonly missed: readonly string[];
}

/** False-positive rate + precision over the graded findings. */
export interface FalsePositiveMetrics {
	readonly total_findings: number;
	readonly true_positive_findings: number;
	readonly false_positive_findings: number;
	readonly unmatched_findings: number;
	readonly false_positive_rate: number | null;
	readonly precision: number | null;
	/** Known-FP label ids reproduced this run. */
	readonly reproduced_fp_ids: readonly string[];
}

/** Dedup precision over cross-scan clusters. */
export interface DedupMetrics {
	readonly clustered_findings: number;
	readonly merged_pairs: number;
	readonly correct_merges: number;
	readonly incorrect_merges: number;
	readonly unlabeled_merges: number;
	readonly dedup_precision: number | null;
}

/** The full scorecard for one run. */
export interface Scorecard {
	readonly schema_version: 1;
	readonly benchmark_id: string;
	readonly release: string;
	readonly recall: RecallMetrics;
	readonly false_positive: FalsePositiveMetrics;
	readonly dedup: DedupMetrics;
	readonly calibration: CalibrationReport;
	readonly notes: readonly string[];
}

function round4(n: number): number {
	return Math.round(n * 10000) / 10000;
}

function ratio(num: number, den: number): number | null {
	return den > 0 ? round4(num / den) : null;
}

/**
 * Stable, order-independent id for a benchmark — a djb2 hash over its sorted vuln
 * + FP ids. Two benchmarks with the same members hash equal, so a scorecard diff
 * can assert it is comparing like with like.
 */
export function benchmarkId(bench: Benchmark): string {
	const ids = [
		...bench.vulns.map((v) => `v:${v.id}`),
		...bench.falsePositives.map((f) => `f:${f.id}`),
	].sort();
	let h = 5381;
	for (const s of ids) {
		for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
	}
	return `bm_${h.toString(16).padStart(8, "0")}`;
}

function recallMetrics(grade: GradeReport): RecallMetrics {
	const missed = grade.coverage.filter((c) => !c.covered).map((c) => c.vulnId);
	const covered = grade.coverage.length - missed.length;
	return {
		ground_truth: grade.coverage.length,
		covered,
		recall: ratio(covered, grade.coverage.length),
		missed,
	};
}

function falsePositiveMetrics(grade: GradeReport): FalsePositiveMetrics {
	let tp = 0;
	let fp = 0;
	let unmatched = 0;
	const reproduced = new Set<string>();
	for (const m of grade.findingMatches) {
		if (m.kind === "true_positive") tp += 1;
		else if (m.kind === "false_positive") {
			fp += 1;
			if (m.fpId) reproduced.add(m.fpId);
		} else unmatched += 1;
	}
	const total = grade.findingMatches.length;
	return {
		total_findings: total,
		true_positive_findings: tp,
		false_positive_findings: fp,
		unmatched_findings: unmatched,
		false_positive_rate: ratio(fp, total),
		precision: ratio(tp, tp + fp),
		reproduced_fp_ids: [...reproduced].sort(),
	};
}

/** Map finding id -> matched ground-truth vuln id (undefined when not a TP). */
function tpVulnByFinding(grade: GradeReport): Map<string, string | undefined> {
	const out = new Map<string, string | undefined>();
	for (const m of grade.findingMatches) {
		out.set(m.findingId, m.kind === "true_positive" ? m.vulnId : undefined);
	}
	return out;
}

function dedupMetrics(
	findings: readonly BenchmarkFinding[],
	grade: GradeReport,
): DedupMetrics {
	const matchedVuln = tpVulnByFinding(grade);
	const clusters = new Map<string, string[]>();
	for (const f of findings) {
		if (!f.clusterId) continue;
		const arr = clusters.get(f.clusterId) ?? [];
		arr.push(f.id);
		clusters.set(f.clusterId, arr);
	}

	let clustered = 0;
	let merged = 0;
	let correct = 0;
	let incorrect = 0;
	let unlabeled = 0;
	for (const members of clusters.values()) {
		if (members.length < 2) continue;
		clustered += members.length;
		for (let i = 0; i < members.length; i++) {
			for (let j = i + 1; j < members.length; j++) {
				merged += 1;
				const a = matchedVuln.get(members[i] as string);
				const b = matchedVuln.get(members[j] as string);
				if (a === undefined || b === undefined) unlabeled += 1;
				else if (a === b) correct += 1;
				else incorrect += 1;
			}
		}
	}
	return {
		clustered_findings: clustered,
		merged_pairs: merged,
		correct_merges: correct,
		incorrect_merges: incorrect,
		unlabeled_merges: unlabeled,
		dedup_precision: ratio(correct, correct + incorrect),
	};
}

/** Build calibration samples from labeled (TP/FP) findings only. */
function calibrationSamples(
	findings: readonly BenchmarkFinding[],
	grade: GradeReport,
): CalibrationSample[] {
	const kindById = new Map<string, MatchKind>(
		grade.findingMatches.map((m) => [m.findingId, m.kind]),
	);
	const samples: CalibrationSample[] = [];
	for (const f of findings) {
		const kind = kindById.get(f.id);
		if (kind !== "true_positive" && kind !== "false_positive") continue;
		const predicted =
			typeof f.confidence === "number" ? f.confidence : confidenceToProb(f.confidenceLabel);
		samples.push({ predicted, label: kind === "true_positive" ? 1 : 0 });
	}
	return samples;
}

/**
 * Compute the full scorecard for one run. Deterministic: identical inputs yield an
 * identical scorecard (no clock/IO).
 */
export function computeScorecard(
	release: string,
	findings: readonly BenchmarkFinding[],
	bench: Benchmark,
	grade: GradeReport,
	calibrationBins = 10,
): Scorecard {
	return {
		schema_version: 1,
		benchmark_id: benchmarkId(bench),
		release,
		recall: recallMetrics(grade),
		false_positive: falsePositiveMetrics(grade),
		dedup: dedupMetrics(findings, grade),
		calibration: computeCalibration(calibrationSamples(findings, grade), calibrationBins),
		notes: [...NOTES],
	};
}
