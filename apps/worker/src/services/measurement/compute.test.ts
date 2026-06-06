// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure `computeReport` math (spec D2) over hand-built FindingRecords — no IO. The
 * end-to-end run over a fixture deliverables set lives in `harness.test.ts`.
 */

import { describe, expect, it } from "vitest";
import type {
	FindingCategory,
	FindingConfidence,
	FindingRecord,
	OracleDisposition,
	Reachability,
	VulnDisposition,
} from "../../job/findings/types.js";
import { computeReport } from "./compute.js";
import type { LoadedFindings } from "./load-findings.js";

interface FindingOver {
	id: string;
	category: string;
	disposition?: VulnDisposition;
	confidence?: FindingConfidence;
	reachability?: Reachability;
	cluster_id?: string;
	oracle_disposition?: OracleDisposition;
}

/** A type-complete FindingRecord with test defaults; optionals set only if given. */
function mkFinding(o: FindingOver): FindingRecord {
	const rec: FindingRecord = {
		id: o.id,
		title: "t",
		category: o.category,
		cwe: "CWE-0",
		owasp_category: "A00",
		severity: "high",
		confidence: o.confidence ?? "firm",
		evidence: "e",
		safe_poc: "p",
		repro_steps: [],
		vulnerable_code_location: { file: "f.ts", line: 1 },
		missing_defense: "m",
		remediation: "r",
		status: "new",
		fingerprint: o.id,
		partialFingerprints: {},
		validation_note: "",
	};
	if (o.disposition !== undefined) rec.disposition = o.disposition;
	if (o.reachability !== undefined) rec.reachability = o.reachability;
	if (o.cluster_id !== undefined) rec.cluster_id = o.cluster_id;
	if (o.oracle_disposition !== undefined) rec.oracle_disposition = o.oracle_disposition;
	return rec;
}

function byCategory(
	over: Partial<Record<FindingCategory, number>>,
): Record<FindingCategory, number> {
	return {
		injection: over.injection ?? 0,
		xss: over.xss ?? 0,
		auth: over.auth ?? 0,
		ssrf: over.ssrf ?? 0,
		authz: over.authz ?? 0,
	};
}

describe("computeReport", () => {
	it("derives yield, precision, distributions and per-category counts", () => {
		const loaded: LoadedFindings = {
			candidates: 6,
			candidatesByCategory: byCategory({ injection: 2, xss: 1, auth: 2, ssrf: 1 }),
			findings: [
				mkFinding({
					id: "I1",
					category: "injection",
					disposition: "exploited",
					confidence: "confirmed",
					reachability: "REACHABLE",
				}),
				mkFinding({ id: "I2", category: "injection", disposition: "blocked", confidence: "firm" }),
				mkFinding({ id: "X1", category: "xss", disposition: "queued", confidence: "tentative" }),
				mkFinding({
					id: "A1",
					category: "auth",
					disposition: "unverified_screen_rejected",
					confidence: "unverified",
				}),
				mkFinding({
					id: "A2",
					category: "auth",
					disposition: "unverified_out_of_scope",
					confidence: "unverified",
				}),
				mkFinding({
					id: "S1",
					category: "ssrf",
					disposition: "blocked",
					confidence: "firm",
					oracle_disposition: "blocked",
				}),
			],
		};

		const r = computeReport("/x", loaded, new Map(), null);

		expect(r.totals).toEqual({ candidates: 6, findings: 6, emitted: 4, confirmed: 1 });
		expect(r.valid_vuln_yield).toBeCloseTo(1 / 6, 4);

		expect(r.precision.confirmed).toBe(1);
		expect(r.precision.false_positives).toBe(3); // A1, A2, S1 (deduped union)
		expect(r.precision.false_positive_breakdown).toEqual({
			screen_refuted: 1,
			oracle_blocked: 1,
			unverified_out_of_scope: 1,
			unverified_total: 2,
		});
		expect(r.precision.precision_proxy).toBeCloseTo(0.25, 4);

		expect(r.distributions.disposition).toMatchObject({
			exploited: 1,
			blocked: 2,
			queued: 1,
			screen_uncertain: 0,
			unverified_out_of_scope: 1,
			unverified_screen_rejected: 1,
		});
		expect(r.distributions.confidence).toMatchObject({
			confirmed: 1,
			firm: 2,
			tentative: 1,
			unverified: 2,
		});
		expect(r.distributions.reachability).toMatchObject({ REACHABLE: 1, unknown: 5 });

		expect(r.dedup).toEqual({ raw_findings: 6, clusters: 6, dedup_ratio: 1 });

		expect(r.per_category.injection).toMatchObject({
			candidates: 2,
			findings: 2,
			emitted: 2,
			confirmed: 1,
			blocked: 1,
		});
		expect(r.per_category.auth).toMatchObject({
			candidates: 2,
			emitted: 0,
			screen_refuted: 1,
			unverified_out_of_scope: 1,
		});
		expect(r.per_category.ssrf).toMatchObject({ oracle_blocked: 1, blocked: 1 });
		expect(r.cost.available).toBe(false);
	});

	it("counts oracle-blocked findings via the oracle map when not on the record", () => {
		const loaded: LoadedFindings = {
			candidates: 1,
			candidatesByCategory: byCategory({ ssrf: 1 }),
			findings: [mkFinding({ id: "S9", category: "ssrf", disposition: "queued" })],
		};
		const r = computeReport("/x", loaded, new Map([["S9", "blocked"]]), null);
		expect(r.precision.false_positives).toBe(1);
		expect(r.precision.false_positive_breakdown.oracle_blocked).toBe(1);
		expect(r.per_category.ssrf?.oracle_blocked).toBe(1);
	});

	it("computes dedup ratio from clusters + unclustered singletons", () => {
		const loaded: LoadedFindings = {
			candidates: 4,
			candidatesByCategory: byCategory({ xss: 4 }),
			findings: [
				mkFinding({ id: "a", category: "xss", cluster_id: "c1" }),
				mkFinding({ id: "b", category: "xss", cluster_id: "c1" }),
				mkFinding({ id: "c", category: "xss", cluster_id: "c2" }),
				mkFinding({ id: "d", category: "xss" }),
			],
		};
		const r = computeReport("/x", loaded, new Map(), null);
		// clusters = {c1, c2} (2) + 1 unclustered singleton = 3, over 4 raw.
		expect(r.dedup).toEqual({ raw_findings: 4, clusters: 3, dedup_ratio: 0.75 });
	});

	it("yields 0 with candidates but null precision when nothing is confirmed/FP", () => {
		const loaded: LoadedFindings = {
			candidates: 2,
			candidatesByCategory: byCategory({ xss: 2 }),
			findings: [
				mkFinding({ id: "a", category: "xss", disposition: "queued" }),
				mkFinding({ id: "b", category: "xss", disposition: "queued" }),
			],
		};
		const r = computeReport("/x", loaded, new Map(), null);
		expect(r.valid_vuln_yield).toBe(0);
		expect(r.precision.precision_proxy).toBeNull();
	});

	it("derives cost-per-valid-finding when cost inputs are present", () => {
		const loaded: LoadedFindings = {
			candidates: 1,
			candidatesByCategory: byCategory({ injection: 1 }),
			findings: [mkFinding({ id: "I1", category: "injection", disposition: "exploited" })],
		};
		const r = computeReport("/x", loaded, new Map(), {
			source: "/x/session.json",
			durationMs: 120000,
			totalTokens: 50000,
		});
		expect(r.cost.available).toBe(true);
		expect(r.cost.duration_ms_per_valid_finding).toBe(120000);
		expect(r.cost.tokens_per_valid_finding).toBe(50000);
	});

	it("emits an all-zero report for an empty finding set", () => {
		const r = computeReport(
			"/empty",
			{ candidates: 0, candidatesByCategory: byCategory({}), findings: [] },
			new Map(),
			null,
		);
		expect(r.totals).toEqual({ candidates: 0, findings: 0, emitted: 0, confirmed: 0 });
		expect(r.valid_vuln_yield).toBeNull();
		expect(r.precision.precision_proxy).toBeNull();
		expect(r.dedup.dedup_ratio).toBeNull();
	});
});
