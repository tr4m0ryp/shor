// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * CVE benchmark + regression-scorecard types (spec T15).
 *
 * The benchmark is a FIXED, labeled ground-truth set (validated scans 0007/0008 +
 * public CVEs) that the engine is graded against on every release so "better over
 * time" becomes falsifiable. Nothing here does IO or LLM work: the grader
 * ({@link ./grader}) and scorecard ({@link ./scorecard}) are pure functions over
 * these injected shapes, so the metric math is unit-tested directly.
 */

import type {
	FindingConfidence,
	FindingSeverity,
} from "../../../job/findings/types.js";

/** Where a labeled item came from — a validated scan or a public advisory. */
export type BenchmarkSource = "scan-0007" | "scan-0008" | "cve";

/**
 * A ground-truth location the grader matches findings against. Mirrors the
 * cve-oracle patch-matcher key (reimplemented clean-room, spec F1): a repo path
 * plus the patched/cited lines, so matching is positional + tolerant of drift.
 */
export interface GroundTruthLocation {
	/** Repo-relative POSIX path of the vulnerable file. */
	readonly file: string;
	/** Primary cited/sink line, when known. */
	readonly line?: number;
	/**
	 * Lines the fix patch DELETES (the cve-oracle signal): a finding whose cited
	 * line lands on/near any of these is a strong positional match.
	 */
	readonly deletedLines?: readonly number[];
	/** Enclosing function / sink symbol, for the substring match tier. */
	readonly symbol?: string;
}

/** One labeled, genuinely-valid vulnerability (a recall target). */
export interface GroundTruthVuln {
	readonly id: string;
	readonly source: BenchmarkSource;
	/** Advisory id when `source === "cve"` (e.g. `CVE-2021-44228`). */
	readonly cveId?: string;
	readonly cwe: string;
	/** Vuln class, aligned to the pipeline's finding categories where possible. */
	readonly category: string;
	readonly severity: FindingSeverity;
	/** Dependency package name — the shortlist key for CVE-style matches. */
	readonly pkg?: string;
	/** Affected version / range string (informational; not range-solved here). */
	readonly affectedVersion?: string;
	/** One or more sink locations; a match on ANY location covers the vuln. */
	readonly locations: readonly GroundTruthLocation[];
	/** Alternate symbol/sink names accepted by the substring match tier. */
	readonly aliases?: readonly string[];
	readonly description: string;
}

/**
 * A labeled KNOWN false positive — a finding shape the pipeline has produced that
 * validation proved wrong (e.g. the scan-0008 path-traversal trio asserting a
 * flow that does not exist). Reproducing one on a later run is a regression.
 */
export interface FalsePositiveLabel {
	readonly id: string;
	readonly source: BenchmarkSource;
	readonly cwe?: string;
	readonly category?: string;
	readonly locations: readonly GroundTruthLocation[];
	readonly reason: string;
}

/** The fixed benchmark: recall targets + known-FP labels. */
export interface Benchmark {
	readonly vulns: readonly GroundTruthVuln[];
	readonly falsePositives: readonly FalsePositiveLabel[];
}

/**
 * The injected finding shape the grader consumes — decoupled from the heavy
 * `FindingRecord` so the grader stays pure and trivially testable. Build one from
 * a real record with {@link ./corpus}.fromFindingRecord.
 */
export interface BenchmarkFinding {
	readonly id: string;
	readonly category?: string;
	readonly cwe?: string;
	readonly pkg?: string;
	readonly version?: string;
	readonly file: string;
	readonly line?: number;
	readonly symbol?: string;
	/** Calibrated P(true-positive) in [0,1], when the pipeline emits one. */
	readonly confidence?: number;
	/** Categorical confidence, used to derive a probability when no number given. */
	readonly confidenceLabel?: FindingConfidence;
	/** Cross-scan cluster id, for dedup-precision. */
	readonly clusterId?: string;
}

/** How one finding resolved against the benchmark. */
export type MatchKind = "true_positive" | "false_positive" | "unmatched";

/** Per-finding grade: what it matched and how strongly. */
export interface FindingMatch {
	readonly findingId: string;
	readonly kind: MatchKind;
	/** Ground-truth vuln id when `kind === "true_positive"`. */
	readonly vulnId?: string;
	/** FP-label id when `kind === "false_positive"`. */
	readonly fpId?: string;
	/** Best positional score in [0,1] for the assigned target. */
	readonly score: number;
}

/** Per-ground-truth coverage: did any finding match it (recall)? */
export interface VulnCoverage {
	readonly vulnId: string;
	readonly covered: boolean;
	/** Finding ids that matched this vuln (may be >1 — the merge signal). */
	readonly matchedBy: readonly string[];
}

/** Full deterministic grade over one finding set vs the benchmark. */
export interface GradeReport {
	readonly findingMatches: readonly FindingMatch[];
	readonly coverage: readonly VulnCoverage[];
}

/** Tunable weights/thresholds for the positional matcher (injected, defaulted). */
export interface GraderOptions {
	/** Minimum combined score to accept a match. */
	readonly matchThreshold: number;
	/** Line-distance (in lines) at which the positional score decays to 0. */
	readonly maxLineDrift: number;
}
