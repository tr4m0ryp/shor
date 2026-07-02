// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Taxonomy traversal tests for the +2 categories (`logic`, `misconfig-web`).
 *
 * Proves each new category travels the SAME path the existing five do:
 *   queue read (queue.ts) → evidence enrichment (evidence.ts) → coverage gate
 *   (gating.ts) → §6.1 mapping (mapping.ts), with the canonical three outcomes —
 *   emitted-when-no-manifest, gated-to-appendix-when-backend-absent, and
 *   exploited-never-gated — plus the CWE/OWASP/enforcing-tier wiring.
 */

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { COVERAGE_MANIFEST_FILENAME } from "../coverage/index.js";
import type { CoverageManifest } from "../coverage/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { CATEGORY_META } from "./category-meta.js";
import { readManualReviewAppendix } from "./gating.js";
import { collectFindings } from "./index.js";
import { FINDING_CATEGORIES, QUEUE_FILES } from "./queue.js";
import type { FindingCategory } from "./types.js";

const logger = {
	info() {},
	warn() {},
	error() {},
} as unknown as ActivityLogger;

const tmpDirs: string[] = [];
async function mkDeliverables(): Promise<string> {
	const dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-taxonomy-"));
	tmpDirs.push(dir);
	return dir;
}

afterEach(async () => {
	for (const d of tmpDirs.splice(0)) {
		await fs.rm(d, { recursive: true, force: true });
	}
});

/** One queue entry per new category, with the queue field names its prompt emits. */
interface NewCategoryCase {
	category: FindingCategory;
	id: string;
	queueEntry: Record<string, unknown>;
	expectedCwe: string;
	expectedOwasp: string;
}

const CASES: NewCategoryCase[] = [
	{
		category: "logic",
		id: "LOGIC-VULN-01",
		queueEntry: {
			ID: "LOGIC-VULN-01",
			vulnerability_type: "WorkflowStateBypass",
			externally_exploitable: true,
			endpoint: "POST /checkout/complete",
			vulnerable_code_location: "src/checkout.ts:88",
			broken_invariant: "ship requires captured payment",
			confidence: "high",
		},
		expectedCwe: "CWE-840",
		expectedOwasp: "A04:2021-Insecure Design",
	},
	{
		category: "misconfig-web",
		id: "MISCFG-VULN-01",
		queueEntry: {
			ID: "MISCFG-VULN-01",
			vulnerability_type: "CORS",
			externally_exploitable: true,
			endpoint: "GET /api/data",
			vulnerable_code_location: "src/cors.ts:12",
			misconfiguration_detail: "ACAO reflects Origin with Allow-Credentials:true",
			confidence: "high",
		},
		expectedCwe: "CWE-16",
		expectedOwasp: "A05:2021-Security Misconfiguration",
	},
];

async function writeQueue(
	dir: string,
	category: FindingCategory,
	entry: Record<string, unknown>,
): Promise<void> {
	await fs.writeFile(
		path.join(dir, QUEUE_FILES[category]),
		JSON.stringify({ vulnerabilities: [entry] }),
	);
}

/** Mark the entry as live-exploited in the per-category evidence markdown. */
async function writeExploitedEvidence(
	dir: string,
	category: FindingCategory,
	id: string,
): Promise<void> {
	const md = [
		"## Successfully Exploited Vulnerabilities",
		"",
		`### ${id}: live-confirmed`,
		"Reached the forbidden state against the running app; impact confirmed.",
		"",
	].join("\n");
	await fs.writeFile(
		path.join(dir, `${category}_exploitation_evidence.md`),
		md,
	);
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

async function writeManifest(dir: string, m: CoverageManifest): Promise<void> {
	await fs.writeFile(
		path.join(dir, COVERAGE_MANIFEST_FILENAME),
		JSON.stringify(m),
	);
}

describe("taxonomy wiring for the +2 categories", () => {
	it("enumerates logic + misconfig-web alongside the existing five", () => {
		expect(FINDING_CATEGORIES).toContain("logic");
		expect(FINDING_CATEGORIES).toContain("misconfig-web");
		expect(FINDING_CATEGORIES).toHaveLength(7);
	});

	for (const c of CASES) {
		it(`${c.category}: queue + meta + enforcing-tier are wired`, () => {
			expect(QUEUE_FILES[c.category]).toBe(`${c.category}_exploitation_queue.json`);
			expect(CATEGORY_META[c.category].defaultCwe).toBe(c.expectedCwe);
			expect(CATEGORY_META[c.category].owasp).toBe(c.expectedOwasp);
		});
	}
});

describe.each(CASES)(
	"category $category traverses the findings pipeline",
	({ category, id, expectedCwe, expectedOwasp, queueEntry }) => {
		it("no-manifest: emitted as a firm §6.1 finding", async () => {
			const dir = await mkDeliverables();
			await writeQueue(dir, category, queueEntry);

			const emitted = await collectFindings(dir, logger);

			const f = emitted.find((rec) => rec.id === id);
			expect(f).toBeDefined();
			expect(f?.category).toBe(category);
			expect(f?.cwe).toBe(expectedCwe);
			expect(f?.owasp_category).toBe(expectedOwasp);
			expect(f?.disposition).toBe("queued");
			// confidence "high" + not exploited => firm (shared mapping).
			expect(f?.confidence).toBe("firm");
			// Backend-enforced classes infer a "medium" baseline when not exploited.
			expect(f?.severity).toBe("medium");
			expect(readManualReviewAppendix(dir, logger)).toEqual([]);
		});

		it("backend-absent: gated to the manual-review appendix, excluded from emitted", async () => {
			const dir = await mkDeliverables();
			await writeQueue(dir, category, queueEntry);
			await writeManifest(dir, manifest("absent"));

			const emitted = await collectFindings(dir, logger);

			expect(emitted.find((rec) => rec.id === id)).toBeUndefined();

			const appendix = readManualReviewAppendix(dir, logger);
			const item = appendix.find((rec) => rec.id === id);
			expect(item).toBeDefined();
			expect(item?.disposition).toBe("unverified_out_of_scope");
			expect(item?.confidence).toBe("unverified");
		});

		it("exploited: NEVER gated, even with backend absent", async () => {
			const dir = await mkDeliverables();
			await writeQueue(dir, category, queueEntry);
			await writeExploitedEvidence(dir, category, id);
			await writeManifest(dir, manifest("absent"));

			const emitted = await collectFindings(dir, logger);

			const f = emitted.find((rec) => rec.id === id);
			expect(f).toBeDefined();
			expect(f?.disposition).toBe("exploited");
			expect(f?.confidence).toBe("confirmed");
			// Exploited escalates the inferred severity one rung.
			expect(f?.severity).toBe("high");
			expect(readManualReviewAppendix(dir, logger)).toEqual([]);
		});
	},
);
