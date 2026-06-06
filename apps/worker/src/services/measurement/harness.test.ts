// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * End-to-end measurement-harness run (spec D2) over a fixture deliverables set
 * written to a temp dir: asserts the reconstructed counts/ratios, that
 * `measurement_report.json` is written, and the read-only invariant (no other
 * deliverable — e.g. the manual-review appendix — is written).
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { generateMeasurementReport, MEASUREMENT_REPORT_FILE } from "./index.js";
import type { MeasurementReport } from "./types.js";

// Silent logger — these tests assert on returned reports / files, not logs.
const logger = {
	info() {},
	warn() {},
	error() {},
} as unknown as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-measure-"));
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const d of tmpDirs.splice(0)) {
		await fs.rm(d, { recursive: true, force: true });
	}
});

/** Write a small but representative per-scan deliverables set. */
async function writeFixture(dir: string): Promise<void> {
	const write = (name: string, body: string): Promise<void> =>
		fs.writeFile(path.join(dir, name), body);

	await write(
		"injection_exploitation_queue.json",
		JSON.stringify({
			vulnerabilities: [
				{
					ID: "INJ-VULN-01",
					vulnerability_type: "sql",
					endpoint: "/login",
					vulnerable_code_location: "src/db.ts:10",
					missing_defense: "parameterize the query",
				},
				{
					ID: "INJ-VULN-02",
					vulnerability_type: "sql",
					endpoint: "/search",
					vulnerable_code_location: "src/q.ts:5",
					missing_defense: "parameterize the query",
				},
			],
		}),
	);
	await write(
		"injection_exploitation_evidence.md",
		[
			"## Successfully Exploited Vulnerabilities",
			"",
			"### INJ-VULN-01: SQL Injection",
			"Confirmed live. Payload executed and returned HTTP 200 with the users table.",
			"",
		].join("\n"),
	);
	await write(
		"auth_exploitation_queue.json",
		JSON.stringify({
			vulnerabilities: [
				{ ID: "AUTH-VULN-01", vulnerability_type: "jwt", endpoint: "/token", missing_defense: "verify signature" },
			],
		}),
	);
	// Adversarial screen refuted the auth hypothesis before exploitation.
	await write(
		"auth_screen_rejected.json",
		JSON.stringify([{ id: "AUTH-VULN-01", screen_reason: "JWT is verified server-side" }]),
	);
	// Oracle adjudication blocked the second injection hypothesis on replay.
	await write(
		"oracle_dispositions.json",
		JSON.stringify([{ id: "INJ-VULN-02", oracle_disposition: "blocked" }]),
	);
	// Audit metrics: duration only (token totals are not persisted here today).
	await write(
		"session.json",
		JSON.stringify({
			session: { id: "scan-1", webUrl: "http://t", status: "completed", createdAt: "2026-01-01T00:00:00Z" },
			metrics: { total_duration_ms: 120000, phases: {}, agents: {} },
		}),
	);
}

describe("generateMeasurementReport (fixture deliverables)", () => {
	it("reconstructs findings read-only and writes the expected report", async () => {
		const dir = await mkDeliverables();
		await writeFixture(dir);

		const report = generateMeasurementReport(dir, logger);

		// 3 raw candidates (2 injection + 1 auth); 1 live-confirmed (INJ-VULN-01).
		expect(report.totals).toEqual({ candidates: 3, findings: 3, emitted: 2, confirmed: 1 });
		expect(report.valid_vuln_yield).toBeCloseTo(1 / 3, 4);

		// FP proxy: AUTH-VULN-01 screen-refuted + INJ-VULN-02 oracle-blocked.
		expect(report.precision.false_positives).toBe(2);
		expect(report.precision.false_positive_breakdown).toMatchObject({
			screen_refuted: 1,
			oracle_blocked: 1,
			unverified_total: 1,
		});
		expect(report.precision.precision_proxy).toBeCloseTo(1 / 3, 4);

		expect(report.per_category.injection).toMatchObject({
			candidates: 2,
			confirmed: 1,
			queued: 1,
			oracle_blocked: 1,
		});
		expect(report.per_category.auth).toMatchObject({ candidates: 1, screen_refuted: 1, emitted: 0 });

		expect(report.cost.available).toBe(true);
		expect(report.cost.duration_ms).toBe(120000);
		expect(report.cost.duration_ms_per_valid_finding).toBe(120000);
		expect(report.cost.total_tokens).toBeNull();

		// The report was persisted and round-trips.
		const onDisk = JSON.parse(
			await fs.readFile(path.join(dir, MEASUREMENT_REPORT_FILE), "utf8"),
		) as MeasurementReport;
		expect(onDisk.totals).toEqual(report.totals);
		expect(onDisk.schema_version).toBe(1);

		// Read-only invariant: measurement never writes the manual-review appendix.
		await expect(
			fs.access(path.join(dir, "manual_review_appendix.json")),
		).rejects.toThrow();
	});
});
