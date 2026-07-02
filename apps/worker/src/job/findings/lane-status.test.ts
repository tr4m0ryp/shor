// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Failed-validation-lane gating regression tests (T5).
 *
 * Core defect this guards against: when an exploitation (validation) agent
 * THROWS, its category's analysis findings were never validated, yet they
 * previously passed through as `firm`/`tentative` as if confirmed — that is what
 * let crashed-SSRF-lane findings pollute the emitted set. A `failed` lane must
 * demote its non-exploited findings to `unverified_out_of_scope` (excluded from
 * the emitted set, routed to the manual-review appendix). A `validated` lane and
 * an absent status file must reproduce the pre-T5 behavior exactly.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { collectFindings } from "./index.js";
import {
	VALIDATION_LANE_STATUS_FILE,
	categoryForExploitAgent,
	readLaneStatus,
	recordExploitLaneOutcome,
	recordLaneStatus,
} from "./lane-status.js";
import type { LaneStatusMap } from "./lane-status.js";

// Silent logger — these tests assert on returned records / files, not logs.
const logger = {
	info() {},
	warn() {},
	error() {},
} as unknown as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-lane-"));
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const d of tmpDirs.splice(0)) {
		await fs.rm(d, { recursive: true, force: true });
	}
});

const SSRF_ID = "SSRF-VULN-01";

/** One ssrf queue entry with NO live evidence (a pure analysis hypothesis). */
async function writeSsrfQueue(dir: string): Promise<void> {
	const queue = {
		vulnerabilities: [
			{
				ID: SSRF_ID,
				source_endpoint: "/api/fetch",
				vulnerable_code_location: "src/fetch.ts:10",
				missing_defense: "no allowlist on the url param",
				vulnerability_type: "service_discovery",
				confidence: "high",
			},
		],
	};
	await fs.writeFile(
		path.join(dir, "ssrf_exploitation_queue.json"),
		JSON.stringify(queue),
	);
}

/** Mark the ssrf entry as live-exploited in the evidence markdown. */
async function writeExploitedEvidence(dir: string): Promise<void> {
	const md = [
		"## Successfully Exploited Vulnerabilities",
		"",
		`### ${SSRF_ID}: SSRF reached the metadata endpoint`,
		"Fetched 169.254.169.254 via the url param.",
		"",
	].join("\n");
	await fs.writeFile(path.join(dir, "ssrf_exploitation_evidence.md"), md);
}

async function writeLaneStatus(dir: string, m: LaneStatusMap): Promise<void> {
	await fs.writeFile(
		path.join(dir, VALIDATION_LANE_STATUS_FILE),
		JSON.stringify(m),
	);
}

async function readAppendix(
	dir: string,
): Promise<{ findings: Array<Record<string, unknown>> } | undefined> {
	const file = path.join(dir, "manual_review_appendix.json");
	try {
		return JSON.parse(await fs.readFile(file, "utf8"));
	} catch {
		return undefined;
	}
}

describe("categoryForExploitAgent", () => {
	it("maps `<cat>-exploit` to its category", () => {
		expect(categoryForExploitAgent("ssrf-exploit")).toBe("ssrf");
		expect(categoryForExploitAgent("injection-exploit")).toBe("injection");
		expect(categoryForExploitAgent("authz-exploit")).toBe("authz");
	});

	it("returns undefined for non-exploit / unknown agents", () => {
		expect(categoryForExploitAgent("ssrf-vuln")).toBeUndefined();
		expect(categoryForExploitAgent("pre-recon")).toBeUndefined();
		expect(categoryForExploitAgent("report")).toBeUndefined();
		expect(categoryForExploitAgent("bogus-exploit")).toBeUndefined();
	});
});

describe("lane-status read/write", () => {
	it("round-trips a recorded status and merges multiple categories", async () => {
		const dir = await mkDeliverables();
		recordLaneStatus(dir, "ssrf", "failed", logger);
		recordLaneStatus(dir, "injection", "validated", logger);
		expect(readLaneStatus(dir, logger)).toEqual({
			ssrf: "failed",
			injection: "validated",
		});
	});

	it("returns an empty map when the file is absent", async () => {
		const dir = await mkDeliverables();
		expect(readLaneStatus(dir, logger)).toEqual({});
	});

	it("recordExploitLaneOutcome no-ops for a non-exploit agent (no file written)", async () => {
		const dir = await mkDeliverables();
		recordExploitLaneOutcome(dir, "ssrf-vuln", "validated", logger);
		expect(readLaneStatus(dir, logger)).toEqual({});
	});

	it("recordExploitLaneOutcome writes the mapped category for an exploit agent", async () => {
		const dir = await mkDeliverables();
		recordExploitLaneOutcome(dir, "ssrf-exploit", "failed", logger);
		expect(readLaneStatus(dir, logger)).toEqual({ ssrf: "failed" });
	});
});

describe("collectFindings failed-lane gating", () => {
	it("failed ssrf lane + unconfirmed ssrf finding => unverified_out_of_scope, excluded", async () => {
		const dir = await mkDeliverables();
		await writeSsrfQueue(dir);
		await writeLaneStatus(dir, { ssrf: "failed" });

		const emitted = await collectFindings(dir, logger);

		// Excluded from the emitted (returned) set.
		expect(emitted.find((f) => f.id === SSRF_ID)).toBeUndefined();
		expect(emitted).toHaveLength(0);

		// Routed to the manual-review appendix with the pinned disposition.
		const appendix = await readAppendix(dir);
		const item = appendix?.findings.find((f) => f.id === SSRF_ID);
		expect(item).toBeDefined();
		expect(item?.disposition).toBe("unverified_out_of_scope");
		// Its confidence must not read as firm/tentative ("as if validated").
		expect(item?.confidence).toBe("unverified");
	});

	it("validated ssrf lane with no exploit => unchanged (firm, emitted)", async () => {
		const dir = await mkDeliverables();
		await writeSsrfQueue(dir);
		await writeLaneStatus(dir, { ssrf: "validated" });

		const emitted = await collectFindings(dir, logger);

		const f = emitted.find((rec) => rec.id === SSRF_ID);
		expect(f).toBeDefined();
		expect(f?.disposition).toBe("queued");
		// confidence "high" + not exploited => firm (unchanged mapping).
		expect(f?.confidence).toBe("firm");
		// No appendix written when nothing is gated out.
		expect(await readAppendix(dir)).toBeUndefined();
	});

	it("absent lane-status file => behaves exactly as before (firm, emitted, no appendix)", async () => {
		const dir = await mkDeliverables();
		await writeSsrfQueue(dir);

		const emitted = await collectFindings(dir, logger);

		const f = emitted.find((rec) => rec.id === SSRF_ID);
		expect(f).toBeDefined();
		expect(f?.confidence).toBe("firm");
		expect(await readAppendix(dir)).toBeUndefined();
	});

	it("exploited finding still stands even when its lane is failed", async () => {
		const dir = await mkDeliverables();
		await writeSsrfQueue(dir);
		await writeExploitedEvidence(dir);
		await writeLaneStatus(dir, { ssrf: "failed" });

		const emitted = await collectFindings(dir, logger);

		const f = emitted.find((rec) => rec.id === SSRF_ID);
		expect(f).toBeDefined();
		expect(f?.disposition).toBe("exploited");
		expect(f?.confidence).toBe("confirmed");
		expect(await readAppendix(dir)).toBeUndefined();
	});
});
