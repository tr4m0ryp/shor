// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Deterministic match-grader (spec T15). Clean-room reimplementation of the
 * cve-oracle patch-matcher CONCEPT (spec F1) — a positional + lexical matcher, NOT
 * a copy of Ali's AGPL code: shortlist by package/CWE/category, then score by
 * path-suffix + line-distance to the patch's deleted/cited lines (tolerant of line
 * drift) + enclosing-symbol substring. Same-file is a HARD gate, so a
 * plausible-but-irrelevant citation in another file can never match (spec F5).
 *
 * Pure over its injected inputs — no IO, no clock, no network. Every finding is
 * assigned to at most one target (its argmax); each ground-truth vuln is "covered"
 * when at least one finding matched it (the recall signal).
 */

import type {
	Benchmark,
	BenchmarkFinding,
	FalsePositiveLabel,
	FindingMatch,
	GradeReport,
	GraderOptions,
	GroundTruthLocation,
	GroundTruthVuln,
	VulnCoverage,
} from "./types.js";

export const DEFAULT_GRADER_OPTIONS: GraderOptions = {
	matchThreshold: 0.5,
	maxLineDrift: 12,
};

function round4(n: number): number {
	return Math.round(n * 10000) / 10000;
}

/** Split a path into normalized, lowercased POSIX segments (drops empties). */
function segments(p: string): string[] {
	return p
		.replace(/\\/g, "/")
		.toLowerCase()
		.split("/")
		.filter((s) => s.length > 0);
}

/**
 * Path score in [0,1] from shared trailing segments (suffix overlap). Basename
 * match is the floor (0.5); each additional matching parent segment adds weight.
 * 0 when the basenames differ — the same-file hard gate.
 */
function pathScore(findingFile: string, gtFile: string): number {
	const a = segments(findingFile);
	const b = segments(gtFile);
	if (a.length === 0 || b.length === 0) return 0;
	let shared = 0;
	for (let i = 1; i <= Math.min(a.length, b.length); i++) {
		if (a[a.length - i] === b[b.length - i]) shared += 1;
		else break;
	}
	if (shared === 0) return 0;
	// basename (0.5) + up to 0.5 more for deeper suffix agreement.
	const deeper = Math.min(shared - 1, 3) / 3;
	return 0.5 + 0.5 * deeper;
}

/** Nearest patched/cited lines for a location (cited line + deleted lines). */
function targetLines(loc: GroundTruthLocation): number[] {
	const out: number[] = [];
	if (typeof loc.line === "number") out.push(loc.line);
	for (const d of loc.deletedLines ?? []) out.push(d);
	return out;
}

/**
 * Line score in [0,1]: 1 on an exact hit, decaying linearly to 0 at `maxDrift`.
 * Neutral (0.6) when the finding or the ground truth omits a line — path + symbol
 * then carry the match, so a location-less advisory is still gradeable.
 */
function lineScore(
	findingLine: number | undefined,
	loc: GroundTruthLocation,
	maxDrift: number,
): number {
	const gtLines = targetLines(loc);
	if (findingLine === undefined || gtLines.length === 0) return 0.6;
	let best = Infinity;
	for (const g of gtLines) best = Math.min(best, Math.abs(findingLine - g));
	if (best >= maxDrift) return 0;
	return 1 - best / maxDrift;
}

/** Symbol bonus in [0,0.15] when the finding symbol matches a sink/alias. */
function symbolScore(
	finding: BenchmarkFinding,
	loc: GroundTruthLocation,
	aliases: readonly string[],
): number {
	const sym = finding.symbol?.toLowerCase().trim();
	if (!sym) return 0;
	const needles = [loc.symbol, ...aliases]
		.filter((s): s is string => !!s)
		.map((s) => s.toLowerCase());
	for (const n of needles) {
		if (n && (sym.includes(n) || n.includes(sym))) return 0.15;
	}
	return 0;
}

function eqCi(a: string | undefined, b: string | undefined): boolean {
	return !!a && !!b && a.toLowerCase() === b.toLowerCase();
}

/**
 * Cheap shortlist gate (the cve-oracle "shortlist by package/CWE" tier). A finding
 * is considered against a vuln when they agree on package OR cwe OR category — or
 * when the finding carries none of those keys (fall through to positional only).
 */
function inShortlist(finding: BenchmarkFinding, vuln: GroundTruthVuln): boolean {
	if (eqCi(finding.pkg, vuln.pkg)) return true;
	const hasKeys = !!finding.cwe || !!finding.category || !!finding.pkg;
	if (!hasKeys) return true;
	return eqCi(finding.cwe, vuln.cwe) || eqCi(finding.category, vuln.category);
}

/** Best positional score of a finding against one location set. */
function bestLocationScore(
	finding: BenchmarkFinding,
	locations: readonly GroundTruthLocation[],
	aliases: readonly string[],
	maxDrift: number,
): number {
	let best = 0;
	for (const loc of locations) {
		const ps = pathScore(finding.file, loc.file);
		if (ps === 0) continue; // same-file hard gate
		const ls = lineScore(finding.line, loc, maxDrift);
		const ss = symbolScore(finding, loc, aliases);
		// path (60%) + line (40%), plus a small symbol bonus, clamped to 1.
		const score = Math.min(1, ps * 0.6 + ls * 0.4 + ss);
		if (score > best) best = score;
	}
	return best;
}

interface Candidate {
	kind: "true_positive" | "false_positive";
	id: string;
	score: number;
}

/** Score a finding against every vuln + FP label; return the argmax candidate. */
function classifyFinding(
	finding: BenchmarkFinding,
	bench: Benchmark,
	opts: GraderOptions,
): Candidate | null {
	let best: Candidate | null = null;
	for (const vuln of bench.vulns) {
		if (!inShortlist(finding, vuln)) continue;
		const score = bestLocationScore(
			finding,
			vuln.locations,
			vuln.aliases ?? [],
			opts.maxLineDrift,
		);
		if (score >= opts.matchThreshold && (!best || score > best.score)) {
			best = { kind: "true_positive", id: vuln.id, score };
		}
	}
	for (const fp of bench.falsePositives) {
		if (!fpKeysAgree(finding, fp)) continue;
		const score = bestLocationScore(finding, fp.locations, [], opts.maxLineDrift);
		if (score >= opts.matchThreshold && (!best || score > best.score)) {
			best = { kind: "false_positive", id: fp.id, score };
		}
	}
	return best;
}

/** Whether a finding's shortlist keys are compatible with an FP label. */
export function fpKeysAgree(
	finding: BenchmarkFinding,
	fp: FalsePositiveLabel,
): boolean {
	if (fp.cwe && finding.cwe && !eqCi(finding.cwe, fp.cwe)) return false;
	if (fp.category && finding.category && !eqCi(finding.category, fp.category)) {
		return false;
	}
	return true;
}

/**
 * Grade a finding set against the benchmark. Deterministic and order-stable: the
 * output `findingMatches` preserve input order; `coverage` preserves benchmark
 * order.
 */
export function gradeFindings(
	findings: readonly BenchmarkFinding[],
	bench: Benchmark,
	options?: Partial<GraderOptions>,
): GradeReport {
	const opts: GraderOptions = { ...DEFAULT_GRADER_OPTIONS, ...options };

	const findingMatches: FindingMatch[] = [];
	const coveredBy = new Map<string, string[]>();

	for (const finding of findings) {
		const cand = classifyFinding(finding, bench, opts);
		if (!cand) {
			findingMatches.push({ findingId: finding.id, kind: "unmatched", score: 0 });
			continue;
		}
		if (cand.kind === "true_positive") {
			findingMatches.push({
				findingId: finding.id,
				kind: "true_positive",
				vulnId: cand.id,
				score: round4(cand.score),
			});
			const arr = coveredBy.get(cand.id) ?? [];
			arr.push(finding.id);
			coveredBy.set(cand.id, arr);
		} else {
			findingMatches.push({
				findingId: finding.id,
				kind: "false_positive",
				fpId: cand.id,
				score: round4(cand.score),
			});
		}
	}

	const coverage: VulnCoverage[] = bench.vulns.map((v) => {
		const matchedBy = coveredBy.get(v.id) ?? [];
		return { vulnId: v.id, covered: matchedBy.length > 0, matchedBy };
	});

	return { findingMatches, coverage };
}
