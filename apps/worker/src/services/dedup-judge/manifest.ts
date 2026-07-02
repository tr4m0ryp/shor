// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Accepted-manifest clustering loop adapted from the Apache-2.0 licensed dedup
// judge harness pattern (https://www.apache.org/licenses/LICENSE-2.0).

/**
 * Root-cause clustering core.
 *
 * Maintains an "accepted manifest" of representative findings and walks the input
 * SERIALLY (no concurrency → no races), asking an injected `judge` whether each
 * candidate is NEW / DUP_BETTER / DUP_SKIP relative to the manifest. Every input
 * finding is returned (nothing is dropped) stamped with a stable `cluster_id`;
 * same root cause → same `cluster_id`. The judge is injected so this loop is
 * unit-testable without an LLM, and so the real LLM judge can fail open to NEW.
 */

import { createHash } from "node:crypto";
import type { Judgment } from "../../ai/structured/index.js";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** One accepted cluster: its stable id + the current cleanest representative. */
export interface ManifestEntry {
	cluster_id: string;
	representative: FindingRecord;
}

/** Judge a candidate against the current manifest. MUST never throw (fail open). */
export type JudgeFn = (
	candidate: FindingRecord,
	manifest: ManifestEntry[],
) => Promise<Judgment>;

/** Inputs to {@link clusterWithJudge}: the judge, a logger, and the manifest cap. */
export interface ClusterCoreOptions {
	judge: JudgeFn;
	logger: ActivityLogger;
	/** Max manifest entries shown to the judge; excess clusters stay singletons. */
	cap: number;
}

/**
 * Stable cluster id seeded from the CLUSTER-CREATING finding (the one that earned
 * a NEW verdict). Derived from its fingerprint (falling back to id / location) so
 * it stays fixed even when the representative is later swapped by DUP_BETTER.
 * Distinct from the §6.1 `fingerprint`, which is left untouched for idempotent
 * re-ingest — `cluster_id` is purely additive grouping identity.
 */
export function clusterIdFor(f: FindingRecord): string {
	const seed =
		(typeof f.fingerprint === "string" && f.fingerprint) ||
		(typeof f.id === "string" && f.id) ||
		`${f.vulnerable_code_location?.file ?? ""}:${f.vulnerable_code_location?.line ?? ""}`;
	return `cl_${createHash("sha1").update(seed).digest("hex").slice(0, 12)}`;
}

/** Return a copy of `f` with `cluster_id` stamped (never mutates the input). */
function withCluster(f: FindingRecord, clusterId: string): FindingRecord {
	return { ...f, cluster_id: clusterId };
}

/**
 * Cluster `findings` by root cause via the injected judge. Returns every finding
 * (input order, none dropped) with a `cluster_id`. DUP_BETTER swaps the cluster's
 * representative in place (id stays stable); DUP_SKIP keeps it. A DUP verdict whose
 * `cluster_id` does not resolve to a live manifest entry fails safe to NEW (no
 * wrong merge, no drop). When the manifest is at `cap`, new clusters are NOT added
 * to it (they stay singletons) and the cap is logged once — never silently.
 */
export async function clusterWithJudge(
	findings: FindingRecord[],
	opts: ClusterCoreOptions,
): Promise<FindingRecord[]> {
	const { judge, logger, cap } = opts;
	const manifest: ManifestEntry[] = [];
	const out: FindingRecord[] = [];
	let created = 0;
	let skipped = 0;
	let improved = 0;
	let capSkipped = 0;
	let capLogged = false;

	const acceptNew = (finding: FindingRecord): void => {
		const clusterId = clusterIdFor(finding);
		out.push(withCluster(finding, clusterId));
		created += 1;
		if (manifest.length < cap) {
			manifest.push({ cluster_id: clusterId, representative: finding });
		} else {
			capSkipped += 1;
			if (!capLogged) {
				capLogged = true;
				logger.warn("Dedup manifest cap reached; further clusters stay singletons", {
					cap,
					totalFindings: findings.length,
				});
			}
		}
	};

	for (const finding of findings) {
		// First finding (or an empty/frozen manifest with a NEW match) needs no LLM.
		if (manifest.length === 0) {
			acceptNew(finding);
			continue;
		}

		const judgment = await judge(finding, manifest);
		const matched =
			judgment.judgment === "NEW"
				? undefined
				: manifest.find((e) => e.cluster_id === judgment.cluster_id);

		if (!matched) {
			// NEW, or a DUP verdict that did not resolve to a live cluster → fail safe.
			acceptNew(finding);
			continue;
		}

		out.push(withCluster(finding, matched.cluster_id));
		if (judgment.judgment === "DUP_BETTER") {
			matched.representative = finding; // swap to the cleaner example; id unchanged
			improved += 1;
		} else {
			skipped += 1;
		}
	}

	logger.info("Dedup clustering complete", {
		findings: findings.length,
		clusters: manifest.length,
		created,
		duplicatesSkipped: skipped,
		representativesImproved: improved,
		cappedSingletons: capSkipped,
	});
	return out;
}
