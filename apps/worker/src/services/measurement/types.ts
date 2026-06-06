// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Measurement-harness report schema (spec D2).
 *
 * `MeasurementReport` is the shape written to
 * `<deliverablesPath>/measurement_report.json`. It quantifies valid-vuln yield so
 * the team can validate the whole effort (and the measure-first lean-prompts
 * decision). Every number is derived read-only from the per-scan deliverables —
 * see {@link ./compute.ts} for the exact definitions, summarized in
 * `MeasurementReport.notes`.
 */

import type {
	FindingConfidence,
	VulnDisposition,
} from "../../job/findings/types.js";

/** Reachability buckets, plus `unknown` for findings with no reachability set. */
export const REACHABILITY_BUCKETS = [
	"REACHABLE",
	"HARNESS_ONLY",
	"UNCLEAR",
	"unknown",
] as const;
export type ReachabilityBucket = (typeof REACHABILITY_BUCKETS)[number];

/** Headline yield counts. */
export interface Totals {
	/** Raw per-category exploitation-queue hypotheses (the yield denominator). */
	candidates: number;
	/** Mapped FindingRecords (emitted + gated-out), one per id. */
	findings: number;
	/** Findings NOT gated out (exploited|blocked|queued) — the POSTed set. */
	emitted: number;
	/** Live-proven findings (disposition `exploited`) — the valid numerator. */
	confirmed: number;
}

/**
 * Per-reason tally of the false-positive proxy. The lines may OVERLAP (a finding
 * can be both `unverified_*` and oracle-blocked), so they need not sum to
 * {@link Precision.false_positives} (the deduped union).
 */
export interface FalsePositiveBreakdown {
	/** disposition `unverified_screen_rejected` (adversarial screen refuted it). */
	screen_refuted: number;
	/** oracle adjudication `blocked` (replay blocked). */
	oracle_blocked: number;
	/** disposition `unverified_out_of_scope` (coverage / failed-lane gate). */
	unverified_out_of_scope: number;
	/** Both `unverified_*` dispositions together. */
	unverified_total: number;
}

/** Precision proxy: confirmed vs the deduped false-positive set. */
export interface Precision {
	confirmed: number;
	/** Deduped union of `unverified_*` and oracle-blocked findings. */
	false_positives: number;
	false_positive_breakdown: FalsePositiveBreakdown;
	/** confirmed / (confirmed + false_positives); null when the denominator is 0. */
	precision_proxy: number | null;
}

/** Clustering yield: distinct clusters vs raw findings. */
export interface Dedup {
	raw_findings: number;
	/** Distinct cluster ids + each unclustered finding as its own singleton. */
	clusters: number;
	/** clusters / raw_findings (<= 1; 1.0 means no clustering applied). */
	dedup_ratio: number | null;
}

/** Count distributions over the full finding set. */
export interface Distributions {
	disposition: Record<VulnDisposition, number>;
	confidence: Record<FindingConfidence, number>;
	reachability: Record<ReachabilityBucket, number>;
}

/** Per-category slice of the yield + precision counts. */
export interface CategoryMeasurement {
	candidates: number;
	findings: number;
	emitted: number;
	confirmed: number;
	blocked: number;
	queued: number;
	screen_refuted: number;
	unverified_out_of_scope: number;
	oracle_blocked: number;
}

/**
 * Best-effort cost numbers from the audit `session.json`. `available` is false
 * when no metrics file was found; the report is still emitted with nulls.
 */
export interface CostMeasurement {
	available: boolean;
	source: string | null;
	duration_ms: number | null;
	total_tokens: number | null;
	/** total_tokens / confirmed; null when tokens are absent or confirmed is 0. */
	tokens_per_valid_finding: number | null;
	/** duration_ms / confirmed; null when duration is absent or confirmed is 0. */
	duration_ms_per_valid_finding: number | null;
}

/** The full measurement report (the JSON written to the deliverables dir). */
export interface MeasurementReport {
	schema_version: 1;
	generated_at: string;
	deliverables_path: string;
	totals: Totals;
	/** confirmed / candidates; null when there are no candidates. */
	valid_vuln_yield: number | null;
	precision: Precision;
	dedup: Dedup;
	distributions: Distributions;
	per_category: Record<string, CategoryMeasurement>;
	cost: CostMeasurement;
	/** Human-readable glossary of how each metric is defined. */
	notes: string[];
}
