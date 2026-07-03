// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scorecard tests: recall / FP-rate / dedup-precision / calibration over a fixture
 * finding set graded against the seed benchmark, plus benchmark_id stability, the
 * cross-run regression diff, the JSON report round-trip, and that the seeded
 * labeled set is consumable by a calibration routine.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import {
	appendEntry,
	BENCHMARK_REPORT_FILE,
	benchmarkId,
	compareEntries,
	computeCalibration,
	latestRegression,
	loadBenchmark,
	runBenchmark,
	SEED_CALIBRATION_EXAMPLES,
	toCalibrationSamples,
	writeBenchmarkReport,
} from "./index.js";
import type { BenchmarkFinding, ScorecardHistory } from "./index.js";

const logger = { info() {}, warn() {}, error() {} } as unknown as ActivityLogger;
const bench = loadBenchmark();
const API = "backend/UvA.Workflow.Api";

/** Six findings: 4 TP (2 clustered-correct, 2 clustered-wrong), 1 FP, 1 novel. */
const FIXTURE: BenchmarkFinding[] = [
	{ id: "F1", file: `${API}/Services/EffectService.cs`, line: 233, cwe: "CWE-918", category: "ssrf", confidenceLabel: "confirmed", clusterId: "c1" },
	{ id: "F2", file: `${API}/Services/EffectService.cs`, line: 235, cwe: "CWE-918", category: "ssrf", confidenceLabel: "confirmed", clusterId: "c1" },
	{ id: "F3", file: `${API}/Controllers/VersionsController.cs`, cwe: "CWE-306", category: "auth", confidenceLabel: "confirmed", clusterId: "c2" },
	{ id: "F6", file: `${API}/Controllers/InvitesController.cs`, cwe: "CWE-862", category: "authz", confidenceLabel: "firm", clusterId: "c2" },
	{ id: "F4", file: `${API}/Providers/FileSystemProvider.cs`, cwe: "CWE-22", category: "injection", confidenceLabel: "firm", clusterId: "c3" },
	{ id: "F5", file: "src/Unknown.cs", cwe: "CWE-000", category: "other", confidenceLabel: "tentative" },
];

const tmpDirs: string[] = [];
afterEach(async () => {
	for (const d of tmpDirs.splice(0)) await fs.rm(d, { recursive: true, force: true });
});

describe("computeScorecard (fixture vs seed benchmark)", () => {
	const report = runBenchmark("v-test", FIXTURE, { generatedAt: "2026-07-03T00:00:00Z" });
	const s = report.scorecard;

	it("computes recall over the ground-truth set", () => {
		expect(s.recall.ground_truth).toBe(bench.vulns.length); // 11
		expect(s.recall.covered).toBe(3); // ssrf, versions, invites
		expect(s.recall.recall).toBeCloseTo(3 / 11, 4);
		expect(s.recall.missed).toContain("gt-0008-committed-keys");
	});

	it("computes FP-rate and precision over labeled findings", () => {
		expect(s.false_positive.total_findings).toBe(6);
		expect(s.false_positive.true_positive_findings).toBe(4);
		expect(s.false_positive.false_positive_findings).toBe(1);
		expect(s.false_positive.unmatched_findings).toBe(1);
		expect(s.false_positive.false_positive_rate).toBeCloseTo(1 / 6, 4);
		expect(s.false_positive.precision).toBeCloseTo(0.8, 4);
		expect(s.false_positive.reproduced_fp_ids).toEqual(["fp-0008-path-traversal-trio"]);
	});

	it("computes dedup precision from same-cluster pairs", () => {
		expect(s.dedup.clustered_findings).toBe(4); // c1 + c2
		expect(s.dedup.merged_pairs).toBe(2);
		expect(s.dedup.correct_merges).toBe(1); // c1: both -> ssrf
		expect(s.dedup.incorrect_merges).toBe(1); // c2: versions vs invites
		expect(s.dedup.dedup_precision).toBeCloseTo(0.5, 4);
	});

	it("computes calibration over the labeled (TP/FP) findings", () => {
		expect(s.calibration.samples).toBe(5); // F5 (unmatched) excluded
		expect(s.calibration.baseRate).toBeCloseTo(0.8, 4);
		expect(s.calibration.ece).toBeCloseTo(0.1, 4);
		expect(s.calibration.mce).toBeCloseTo(0.1, 4);
		expect(s.calibration.brier).toBeCloseTo(0.11, 4);
	});
});

describe("benchmarkId", () => {
	it("is stable and order-independent", () => {
		const id = benchmarkId(bench);
		expect(id).toMatch(/^bm_[0-9a-f]{8}$/);
		const shuffled = { vulns: [...bench.vulns].reverse(), falsePositives: [...bench.falsePositives] };
		expect(benchmarkId(shuffled)).toBe(id);
	});
});

describe("regression tracking", () => {
	it("flags a recall drop / FP-rate rise on the same benchmark", () => {
		const good = runBenchmark("v1", FIXTURE, { generatedAt: "2026-07-03T00:00:00Z" }).entry;
		// A later run that only reproduces the FP and covers nothing.
		const bad = runBenchmark("v2", [FIXTURE[4]!], { generatedAt: "2026-07-04T00:00:00Z" }).entry;
		const diff = compareEntries(good, bad);
		expect(diff.same_benchmark).toBe(true);
		expect(diff.regressed).toBe(true);
		expect(diff.recall_delta).toBeLessThan(0);
		expect(diff.false_positive_rate_delta).toBeGreaterThan(0);
	});

	it("does not flag an improvement, and marks a benchmark change invalid", () => {
		const v1 = runBenchmark("v1", [FIXTURE[4]!], { generatedAt: "2026-07-03T00:00:00Z" }).entry;
		const v2 = runBenchmark("v2", FIXTURE, { generatedAt: "2026-07-04T00:00:00Z" }).entry;
		expect(compareEntries(v1, v2).regressed).toBe(false);

		const forked = { ...v2, benchmark_id: "bm_deadbeef" };
		const diff = compareEntries(v1, forked);
		expect(diff.same_benchmark).toBe(false);
		expect(diff.regressed).toBe(true);
	});

	it("diffs the last two entries of a history", () => {
		let history: ScorecardHistory = { entries: [] };
		history = appendEntry(history, runBenchmark("v1", FIXTURE, { generatedAt: "t1" }).entry);
		expect(latestRegression(history)).toBeNull();
		history = appendEntry(history, runBenchmark("v2", [FIXTURE[4]!], { generatedAt: "t2" }).entry);
		expect(latestRegression(history)?.regressed).toBe(true);
	});
});

describe("JSON report emission", () => {
	it("writes benchmark_scorecard.json and round-trips", async () => {
		const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-bench-"));
		tmpDirs.push(dir);
		const report = runBenchmark("v-test", FIXTURE, { generatedAt: "2026-07-03T00:00:00Z" });
		writeBenchmarkReport(dir, report, logger);
		const onDisk = JSON.parse(
			await fs.readFile(path.join(dir, BENCHMARK_REPORT_FILE), "utf8"),
		) as typeof report;
		expect(onDisk.schema_version).toBe(1);
		expect(onDisk.scorecard.recall.recall).toBeCloseTo(3 / 11, 4);
		expect(onDisk.entry.benchmark_id).toBe(benchmarkId(bench));
	});
});

describe("seeded labeled set is consumable by a calibration routine", () => {
	it("feeds toCalibrationSamples -> computeCalibration with real slope", () => {
		const samples = toCalibrationSamples(SEED_CALIBRATION_EXAMPLES);
		expect(samples.length).toBe(SEED_CALIBRATION_EXAMPLES.length);
		expect(samples.every((s) => s.predicted >= 0 && s.predicted <= 1)).toBe(true);
		const cal = computeCalibration(samples);
		// The seed deliberately encodes confident-but-wrong cases, so ECE > 0.
		expect(cal.ece).not.toBeNull();
		expect(cal.ece as number).toBeGreaterThan(0);
		expect(cal.baseRate).toBeCloseTo(7 / 12, 4);
	});
});
