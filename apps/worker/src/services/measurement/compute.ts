// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Pure measurement computations (spec D2): turn the loaded FindingRecord set, the
 * oracle dispositions, and the best-effort cost inputs into a MeasurementReport.
 * No IO — every function here is deterministic over its arguments, so the metric
 * math is unit-tested directly without a deliverables fixture.
 */

import type {
	FindingConfidence,
	FindingRecord,
	OracleDisposition,
	VulnDisposition,
} from "../../job/findings/types.js";
import type { CostInputs } from "./cost.js";
import type { LoadedFindings } from "./load-findings.js";
import { REACHABILITY_BUCKETS } from "./types.js";
import type {
	CategoryMeasurement,
	CostMeasurement,
	Dedup,
	Distributions,
	MeasurementReport,
	ReachabilityBucket,
} from "./types.js";

const DISPOSITIONS: readonly VulnDisposition[] = [
	"exploited",
	"blocked",
	"queued",
	"screen_uncertain",
	"unverified_out_of_scope",
	"unverified_screen_rejected",
];

const CONFIDENCES: readonly FindingConfidence[] = [
	"confirmed",
	"firm",
	"tentative",
	"unverified",
];

const NOTES: readonly string[] = [
	"candidates = raw per-category exploitation-queue hypotheses (the yield denominator).",
	"confirmed = findings with disposition 'exploited' (live-proven); the valid-vuln numerator.",
	"emitted = findings not gated out (exploited|blocked|queued) — the set POSTed to the dashboard.",
	"valid_vuln_yield = confirmed / candidates.",
	"false_positives = deduped union of unverified_* (screen-refuted + out-of-scope) and oracle-blocked findings; the breakdown lines may overlap and need not sum to it.",
	"precision_proxy = confirmed / (confirmed + false_positives); a proxy for precision, not ground truth.",
	"dedup_ratio = clusters / raw_findings; 1.0 means no clustering was applied (cluster_id absent).",
	"reachability/cluster_id/oracle_disposition are read from the findings when present; absent reachability falls into the 'unknown' bucket.",
];

/** Per-finding boolean lenses, so every count uses one consistent rule. */
interface Flags {
	confirmed: boolean;
	emitted: boolean;
	screenRefuted: boolean;
	unverifiedOOS: boolean;
	unverified: boolean;
	oracleBlocked: boolean;
	falsePositive: boolean;
}

function isGatedOut(d: VulnDisposition | undefined): boolean {
	return d === "unverified_out_of_scope" || d === "unverified_screen_rejected";
}

function classify(
	f: FindingRecord,
	oracle: Map<string, OracleDisposition>,
): Flags {
	const d = f.disposition;
	const screenRefuted = d === "unverified_screen_rejected";
	const unverifiedOOS = d === "unverified_out_of_scope";
	const unverified = screenRefuted || unverifiedOOS;
	const effectiveOracle = f.oracle_disposition ?? oracle.get(String(f.id));
	const oracleBlocked = effectiveOracle === "blocked";
	return {
		confirmed: d === "exploited",
		emitted: !isGatedOut(d),
		screenRefuted,
		unverifiedOOS,
		unverified,
		oracleBlocked,
		falsePositive: unverified || oracleBlocked,
	};
}

function round(n: number): number {
	return Math.round(n * 10000) / 10000;
}

function ratio(numerator: number, denominator: number): number | null {
	return denominator > 0 ? round(numerator / denominator) : null;
}

function zero<K extends string>(keys: readonly K[]): Record<K, number> {
	const out = {} as Record<K, number>;
	for (const k of keys) out[k] = 0;
	return out;
}

function bucketReachability(r: FindingRecord["reachability"]): ReachabilityBucket {
	if (r === "REACHABLE" || r === "HARNESS_ONLY" || r === "UNCLEAR") return r;
	return "unknown";
}

function distributions(findings: FindingRecord[]): Distributions {
	const disposition = zero(DISPOSITIONS);
	const confidence = zero(CONFIDENCES);
	const reachability = zero(REACHABILITY_BUCKETS);
	for (const f of findings) {
		if (f.disposition) disposition[f.disposition] += 1;
		confidence[f.confidence] += 1;
		reachability[bucketReachability(f.reachability)] += 1;
	}
	return { disposition, confidence, reachability };
}

function dedup(findings: FindingRecord[]): Dedup {
	const clusterIds = new Set<string>();
	let unclustered = 0;
	for (const f of findings) {
		const id = typeof f.cluster_id === "string" ? f.cluster_id.trim() : "";
		if (id) clusterIds.add(id);
		else unclustered += 1;
	}
	const clusters = clusterIds.size + unclustered;
	return {
		raw_findings: findings.length,
		clusters,
		dedup_ratio: ratio(clusters, findings.length),
	};
}

function freshCategory(candidates: number): CategoryMeasurement {
	return {
		candidates,
		findings: 0,
		emitted: 0,
		confirmed: 0,
		blocked: 0,
		queued: 0,
		screen_refuted: 0,
		unverified_out_of_scope: 0,
		oracle_blocked: 0,
	};
}

function perCategory(
	loaded: LoadedFindings,
	oracle: Map<string, OracleDisposition>,
): Record<string, CategoryMeasurement> {
	const out: Record<string, CategoryMeasurement> = {};
	for (const [cat, n] of Object.entries(loaded.candidatesByCategory)) {
		out[cat] = freshCategory(n);
	}
	for (const f of loaded.findings) {
		const c = (out[f.category] ??= freshCategory(0));
		const fl = classify(f, oracle);
		c.findings += 1;
		if (fl.emitted) c.emitted += 1;
		if (fl.confirmed) c.confirmed += 1;
		if (f.disposition === "blocked") c.blocked += 1;
		if (f.disposition === "queued") c.queued += 1;
		if (fl.screenRefuted) c.screen_refuted += 1;
		if (fl.unverifiedOOS) c.unverified_out_of_scope += 1;
		if (fl.oracleBlocked) c.oracle_blocked += 1;
	}
	return out;
}

function costMeasurement(
	cost: CostInputs | null,
	confirmed: number,
): CostMeasurement {
	if (!cost) {
		return {
			available: false,
			source: null,
			duration_ms: null,
			total_tokens: null,
			tokens_per_valid_finding: null,
			duration_ms_per_valid_finding: null,
		};
	}
	const per = (value: number | null): number | null =>
		value !== null && confirmed > 0 ? round(value / confirmed) : null;
	return {
		available: cost.durationMs !== null || cost.totalTokens !== null,
		source: cost.source,
		duration_ms: cost.durationMs,
		total_tokens: cost.totalTokens,
		tokens_per_valid_finding: per(cost.totalTokens),
		duration_ms_per_valid_finding: per(cost.durationMs),
	};
}

/**
 * Compute the full {@link MeasurementReport} from the read-only inputs. Pure: the
 * only non-determinism is `generated_at` (wall-clock at call time).
 */
export function computeReport(
	deliverablesPath: string,
	loaded: LoadedFindings,
	oracle: Map<string, OracleDisposition>,
	cost: CostInputs | null,
): MeasurementReport {
	const findings = loaded.findings;

	let confirmed = 0;
	let emitted = 0;
	let screenRefuted = 0;
	let unverifiedOOS = 0;
	let unverifiedTotal = 0;
	let oracleBlocked = 0;
	let falsePositives = 0;
	for (const f of findings) {
		const fl = classify(f, oracle);
		if (fl.confirmed) confirmed += 1;
		if (fl.emitted) emitted += 1;
		if (fl.screenRefuted) screenRefuted += 1;
		if (fl.unverifiedOOS) unverifiedOOS += 1;
		if (fl.unverified) unverifiedTotal += 1;
		if (fl.oracleBlocked) oracleBlocked += 1;
		if (fl.falsePositive) falsePositives += 1;
	}

	return {
		schema_version: 1,
		generated_at: new Date().toISOString(),
		deliverables_path: deliverablesPath,
		totals: {
			candidates: loaded.candidates,
			findings: findings.length,
			emitted,
			confirmed,
		},
		valid_vuln_yield: ratio(confirmed, loaded.candidates),
		precision: {
			confirmed,
			false_positives: falsePositives,
			false_positive_breakdown: {
				screen_refuted: screenRefuted,
				oracle_blocked: oracleBlocked,
				unverified_out_of_scope: unverifiedOOS,
				unverified_total: unverifiedTotal,
			},
			precision_proxy: ratio(confirmed, confirmed + falsePositives),
		},
		dedup: dedup(findings),
		distributions: distributions(findings),
		per_category: perCategory(loaded, oracle),
		cost: costMeasurement(cost, confirmed),
		notes: [...NOTES],
	};
}
