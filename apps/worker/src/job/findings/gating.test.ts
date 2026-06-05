// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Coverage gating regression tests (T3).
 *
 * The core defect this guards against: today EVERY analysis-queue entry becomes
 * an emitted finding (only at lower confidence). With a coverage manifest that
 * marks the enforcing tier not-covered, an unconfirmed finding must instead
 * become `unverified_out_of_scope` and be EXCLUDED from the emitted set (routed
 * to a manual-review appendix). Exploited findings are never gated; with no
 * manifest, nothing is gated (no regression for full-stack scans).
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { COVERAGE_MANIFEST_FILENAME } from "../coverage/index.js";
import type { CoverageManifest } from "../coverage/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { collectFindings } from "./index.js";
import { readManualReviewAppendix } from "./gating.js";

// Silent logger — these tests assert on returned records / files, not logs.
const logger = {
	info() {},
	warn() {},
	error() {},
} as unknown as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-gating-"));
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const d of tmpDirs.splice(0)) {
		await fs.rm(d, { recursive: true, force: true });
	}
});

const AUTHZ_ID = "AUTHZ-VULN-01";

/** One authz queue entry with NO live evidence (a pure analysis hypothesis). */
async function writeAuthzQueue(dir: string): Promise<void> {
	const queue = {
		vulnerabilities: [
			{
				ID: AUTHZ_ID,
				endpoint: "/admin/users",
				vulnerable_code_location: "src/routes/admin.ts:42",
				guard_evidence: "no role check before the handler",
				vulnerability_type: "horizontal",
				confidence: "high",
			},
		],
	};
	await fs.writeFile(
		path.join(dir, "authz_exploitation_queue.json"),
		JSON.stringify(queue),
	);
}

/** Mark the authz entry as live-exploited in the evidence markdown. */
async function writeExploitedEvidence(dir: string): Promise<void> {
	const md = [
		"## Successfully Exploited Vulnerabilities",
		"",
		`### ${AUTHZ_ID}: IDOR on /admin/users`,
		"Accessed another tenant's records by tampering the id.",
		"",
	].join("\n");
	await fs.writeFile(path.join(dir, "authz_exploitation_evidence.md"), md);
}

function manifest(backend: "present" | "absent" | "partial"): CoverageManifest {
	return {
		tiers: {
			frontend: "present",
			backend,
			config: "absent",
			schema: "absent",
			tests: "absent",
		},
		observedLiveOnly: [],
		notes: "",
	};
}

async function writeManifest(
	dir: string,
	m: CoverageManifest,
): Promise<void> {
	await fs.writeFile(
		path.join(dir, COVERAGE_MANIFEST_FILENAME),
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

describe("collectFindings coverage gating", () => {
	it("canonical: backend-absent manifest gates an unconfirmed backend finding", async () => {
		const dir = await mkDeliverables();
		await writeAuthzQueue(dir);
		await writeManifest(dir, manifest("absent"));

		const emitted = collectFindings(dir, logger);

		// Excluded from the emitted (returned) set.
		expect(emitted.find((f) => f.id === AUTHZ_ID)).toBeUndefined();
		expect(emitted).toHaveLength(0);

		// Routed to the manual-review appendix with the pinned disposition.
		const appendix = await readAppendix(dir);
		const item = appendix?.findings.find((f) => f.id === AUTHZ_ID);
		expect(item).toBeDefined();
		expect(item?.disposition).toBe("unverified_out_of_scope");
		// Its confidence must not read as firm/tentative ("as if seen").
		expect(item?.confidence).toBe("unverified");
	});

	it("control: backend-present manifest emits the same finding as before", async () => {
		const dir = await mkDeliverables();
		await writeAuthzQueue(dir);
		await writeManifest(dir, manifest("present"));

		const emitted = collectFindings(dir, logger);

		const f = emitted.find((rec) => rec.id === AUTHZ_ID);
		expect(f).toBeDefined();
		expect(f?.disposition).toBe("queued");
		// confidence "high" + not exploited => firm (unchanged mapping).
		expect(f?.confidence).toBe("firm");
		// No appendix written when nothing is gated out.
		expect(await readAppendix(dir)).toBeUndefined();
	});

	it("no-manifest: behaves exactly as today (finding emitted, no appendix)", async () => {
		const dir = await mkDeliverables();
		await writeAuthzQueue(dir);

		const emitted = collectFindings(dir, logger);

		const f = emitted.find((rec) => rec.id === AUTHZ_ID);
		expect(f).toBeDefined();
		expect(f?.confidence).toBe("firm");
		expect(await readAppendix(dir)).toBeUndefined();
	});

	it("exploited findings are NEVER gated out, even with backend absent", async () => {
		const dir = await mkDeliverables();
		await writeAuthzQueue(dir);
		await writeExploitedEvidence(dir);
		await writeManifest(dir, manifest("absent"));

		const emitted = collectFindings(dir, logger);

		const f = emitted.find((rec) => rec.id === AUTHZ_ID);
		expect(f).toBeDefined();
		expect(f?.disposition).toBe("exploited");
		expect(f?.confidence).toBe("confirmed");
		expect(await readAppendix(dir)).toBeUndefined();
	});
});
