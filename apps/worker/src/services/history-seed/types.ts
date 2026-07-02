// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Historical-exploit seed model (spec decision T4).
 *
 * Mines the cloned repo's OWN history — security/fix commits, dependency CVEs —
 * to seed discovery hypotheses ("what's been exploited before"). The
 * `git-security-history` skill writes this shape to
 * `.storron/deliverables/historical_signal.json`; task 005's context-assembler
 * reads it back and renders `{{HISTORICAL_SEED}}` for downstream agents.
 *
 * Shape and filename are a shared contract — consumers import from here, they do
 * not redefine the type. All fields are NON-SECRET by construction: file paths,
 * commit shas/dates/subjects, and SCA package/version/CVE metadata only. Any
 * secret-looking value is redacted by the normalizer before it is persisted.
 */

/** One security/fix-related commit that touched a hot file. */
export interface HistCommit {
	/** Abbreviated or full commit sha. */
	readonly sha: string;
	/** Author/commit date as `YYYY-MM-DD` (best-effort). */
	readonly date: string;
	/** Commit subject line, redacted + length-capped. */
	readonly subject: string;
}

/** A file repeatedly touched by security/fix commits — re-examine first. */
export interface HotFile {
	/** Repo-relative POSIX path. */
	readonly file: string;
	/** Security/fix commits that touched this file, newest first. */
	readonly commits: readonly HistCommit[];
	/** CVE ids referenced by those commits (e.g. `CVE-2021-44228`), if any. */
	readonly cves?: readonly string[];
}

/** A known-vulnerable dependency surfaced by an SCA tool (osv-scanner). */
export interface DepCve {
	/** Package name as the ecosystem reports it. */
	readonly package: string;
	/** Installed/locked version. */
	readonly version: string;
	/** Advisory id (OSV/GHSA/CVE). */
	readonly id: string;
	/** Severity label (`CRITICAL`/`HIGH`/… or a CVSS string); `unknown` if absent. */
	readonly severity: string;
	/** First fixed version, when the advisory provides one. */
	readonly fixedVersion?: string;
}

/** Top-level historical-signal deliverable. */
export interface HistoricalSignal {
	readonly hotFiles: readonly HotFile[];
	readonly depCves: readonly DepCve[];
}

/** Canonical deliverable filename — pinned by the T4 contract. */
export const HISTORICAL_SIGNAL_FILENAME = "historical_signal.json";

/** Caps so a pathological history cannot bloat the prompt. */
export const HISTORY_CAPS = {
	/** Max hot files retained (ranked by commit count, then recency). */
	hotFiles: 40,
	/** Max commits listed per hot file. */
	commitsPerFile: 8,
	/** Max dependency CVEs retained. */
	depCves: 60,
	/** Max CVE ids retained per hot file. */
	cvesPerFile: 12,
	/** Commit subjects longer than this are truncated. */
	subjectLen: 200,
} as const;

/** An empty, well-formed signal (used as the safe default). */
export const EMPTY_HISTORICAL_SIGNAL: HistoricalSignal = {
	hotFiles: [],
	depCves: [],
};
