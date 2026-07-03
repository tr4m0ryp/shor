// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * CVE benchmark + match-grader + regression scorecard (spec T15) — public surface.
 *
 * `runBenchmark` is the one entry point: it grades a finding set against the fixed
 * benchmark and returns the full scorecard. `writeBenchmarkReport` persists the
 * small JSON report. Everything downstream (the recall/FP/dedup/calibration math)
 * is pure and re-exported here so callers import from the module root.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { FindingRecord } from "../../../job/findings/types.js";
import { fromFindingRecord, loadBenchmark } from "./corpus.js";
import { gradeFindings } from "./grader.js";
import { computeScorecard } from "./scorecard.js";
import { toEntry } from "./regression.js";
import type { Scorecard } from "./scorecard.js";
import type { ScorecardEntry } from "./regression.js";
import type { Benchmark, BenchmarkFinding, GradeReport, GraderOptions } from "./types.js";

export * from "./types.js";
export {
	SEED_BENCHMARK,
	loadBenchmark,
	fromFindingRecord,
	confidenceToProb,
} from "./corpus.js";
export { gradeFindings, DEFAULT_GRADER_OPTIONS, fpKeysAgree } from "./grader.js";
export { computeScorecard, benchmarkId } from "./scorecard.js";
export type {
	Scorecard,
	RecallMetrics,
	FalsePositiveMetrics,
	DedupMetrics,
} from "./scorecard.js";
export { computeCalibration } from "./calibration.js";
export type {
	CalibrationReport,
	CalibrationBin,
	CalibrationSample,
} from "./calibration.js";
export {
	toEntry,
	appendEntry,
	compareEntries,
	latestRegression,
	REGRESSION_EPSILON,
} from "./regression.js";
export type {
	ScorecardEntry,
	ScorecardHistory,
	RegressionReport,
} from "./regression.js";
export {
	SEED_CALIBRATION_EXAMPLES,
	SEED_DEDUP_PAIRS,
	toCalibrationSamples,
} from "./seed-sets.js";
export type {
	CalibrationExample,
	DedupPair,
	DedupFeatures,
} from "./seed-sets.js";

/** Filename of the small JSON report written by {@link writeBenchmarkReport}. */
export const BENCHMARK_REPORT_FILE = "benchmark_scorecard.json";

/** The exported benchmark report: grade + scorecard + a compact history entry. */
export interface BenchmarkReport {
	readonly schema_version: 1;
	readonly generated_at: string;
	readonly grade: GradeReport;
	readonly scorecard: Scorecard;
	/** The scorecard reduced to the row that appends to a regression history. */
	readonly entry: ScorecardEntry;
}

/** Options for a benchmark run (all optional; sensible defaults). */
export interface RunBenchmarkOptions {
	/** Override the fixed seed benchmark (tests / a future exported labels file). */
	readonly benchmark?: Benchmark;
	/** Grader threshold/drift overrides. */
	readonly grader?: Partial<GraderOptions>;
	/** Reliability-diagram bin count (default 10). */
	readonly calibrationBins?: number;
	/** Injected timestamp for determinism; defaults to wall-clock. */
	readonly generatedAt?: string;
}

/**
 * Grade `findings` against the benchmark and compute the release scorecard. Pure
 * apart from the default `generated_at` (inject `options.generatedAt` for a fully
 * deterministic result).
 */
export function runBenchmark(
	release: string,
	findings: readonly BenchmarkFinding[],
	options: RunBenchmarkOptions = {},
): BenchmarkReport {
	const bench = options.benchmark ?? loadBenchmark();
	const grade = gradeFindings(findings, bench, options.grader);
	const scorecard = computeScorecard(
		release,
		findings,
		bench,
		grade,
		options.calibrationBins,
	);
	const generatedAt = options.generatedAt ?? new Date().toISOString();
	return {
		schema_version: 1,
		generated_at: generatedAt,
		grade,
		scorecard,
		entry: toEntry(scorecard, generatedAt),
	};
}

/**
 * Convenience: grade live {@link FindingRecord}s by adapting them first. Same
 * result as mapping through {@link fromFindingRecord} yourself.
 */
export function runBenchmarkOnRecords(
	release: string,
	findings: readonly FindingRecord[],
	options: RunBenchmarkOptions = {},
): BenchmarkReport {
	return runBenchmark(release, findings.map(fromFindingRecord), options);
}

/**
 * Persist the report as `<dir>/benchmark_scorecard.json`. A write failure is
 * logged and swallowed — the in-memory report is still returned (mirrors
 * `generateMeasurementReport`). The lone side effect in this module.
 */
export function writeBenchmarkReport(
	dir: string,
	report: BenchmarkReport,
	logger: ActivityLogger,
): BenchmarkReport {
	const file = path.join(dir, BENCHMARK_REPORT_FILE);
	try {
		fs.writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);
		logger.info("Wrote benchmark scorecard", {
			file,
			release: report.scorecard.release,
			recall: report.scorecard.recall.recall,
			false_positive_rate: report.scorecard.false_positive.false_positive_rate,
		});
	} catch (err) {
		logger.warn("Failed to write benchmark scorecard; returning in-memory copy", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return report;
}
