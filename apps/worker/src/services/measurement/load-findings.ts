// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Read-only reconstruction of the per-scan FindingRecord set from the
 * deliverables, for the measurement harness. Mirrors the read path of
 * `collectFindings` but WITHOUT its write side-effects:
 *   - reads the per-category exploitation queues (the raw candidates),
 *   - enriches each with its exploitation-evidence disposition + prose,
 *   - applies the adversarial-screen verdicts and oracle adjudication in-memory,
 *   - maps to `FindingRecord[]`, then merges the AUTHORITATIVE manual-review
 *     appendix (the gated-out `unverified_*` set the pipeline already wrote) by
 *     id, so coverage / failed-lane gating is reflected without re-running — or
 *     re-writing — it.
 *
 * Pure/read-only: it never writes a deliverable, never invokes an agent, and
 * makes no network call. The lone write in this service is the report itself
 * (see {@link ./index.ts}).
 */

import { readManualReviewAppendix } from "../../job/findings/gating.js";
import {
	lookupEvidence,
	readEvidence,
} from "../../job/findings/evidence.js";
import { toFindingRecords } from "../../job/findings/mapping.js";
import { FINDING_CATEGORIES, readQueues } from "../../job/findings/queue.js";
import type {
	FindingCategory,
	FindingRecord,
} from "../../job/findings/types.js";
import { applyOracleDispositions } from "../oracle/index.js";
import { applyScreenVerdicts } from "../screen-verdicts/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** The reconstructed finding set plus the raw candidate counts. */
export interface LoadedFindings {
	/** All mapped findings (emitted + gated-out), one record per id. */
	findings: FindingRecord[];
	/** Raw exploitation-queue hypotheses, total. */
	candidates: number;
	/** Raw exploitation-queue hypotheses, per category. */
	candidatesByCategory: Record<FindingCategory, number>;
}

function emptyByCategory(): Record<FindingCategory, number> {
	return { injection: 0, xss: 0, auth: 0, ssrf: 0, authz: 0 };
}

/**
 * Reconstruct the full FindingRecord set (and candidate counts) from
 * `deliverablesPath`, read-only. Missing/malformed deliverables are tolerated by
 * the underlying readers (best-effort, never fatal).
 */
export function loadFindings(
	deliverablesPath: string,
	logger: ActivityLogger,
): LoadedFindings {
	const vulns = readQueues(deliverablesPath, logger);

	// Raw candidate counts BEFORE any enrichment (the yield denominator). Captured
	// here because the screen pass may synthesize extra entries downstream.
	const candidatesByCategory = emptyByCategory();
	for (const v of vulns) candidatesByCategory[v.category] += 1;
	const candidates = vulns.length;

	// Enrich each vuln with its evidence disposition + prose (mirrors collectFindings).
	const evidenceByCategory = new Map(
		FINDING_CATEGORIES.map((c) => [c, readEvidence(deliverablesPath, c, logger)]),
	);
	for (const vuln of vulns) {
		const map = evidenceByCategory.get(vuln.category);
		const entry = map ? lookupEvidence(map, vuln.id) : undefined;
		if (entry) {
			vuln.disposition = entry.disposition;
			vuln.evidenceText = entry.text;
		}
	}

	// In-memory adjudication passes (no writes). `applyScreenVerdicts` stamps
	// screen-refuted hypotheses `unverified_screen_rejected`; `applyOracleDispositions`
	// is identity until task 013 fills it. Both mutate the in-memory array only.
	applyScreenVerdicts(vulns, deliverablesPath, logger);
	applyOracleDispositions(vulns, deliverablesPath, logger);

	const base = toFindingRecords(vulns);

	// Merge the authoritative gated-out set (`unverified_out_of_scope` /
	// `unverified_screen_rejected`) the pipeline already persisted. Keyed by id so a
	// gated finding overrides its pre-gate (queued/blocked) twin and nothing is
	// double-counted; an absent appendix (gating never ran) simply leaves `base`.
	const byId = new Map<string, FindingRecord>();
	for (const f of base) byId.set(String(f.id), f);
	for (const f of readManualReviewAppendix(deliverablesPath, logger)) {
		byId.set(String(f.id), f);
	}

	return { findings: [...byId.values()], candidates, candidatesByCategory };
}
