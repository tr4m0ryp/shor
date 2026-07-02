// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Defensive read-side normalizer for the historical-exploit seed.
 *
 * `normalizeHistoricalSignal(value)` coerces any parsed value (the skill's
 * `historical_signal.json`, or raw skill stdout already parsed to JSON) into a
 * well-formed `HistoricalSignal`: it drops malformed entries, dedups commits by
 * sha, enforces the `HISTORY_CAPS`, backfills each hot file's `cves` from its
 * commit subjects, and REDACTS any secret-looking token. Pure, never throws —
 * mirrors `normalizeManifest` in the coverage module.
 */

import {
	EMPTY_HISTORICAL_SIGNAL,
	HISTORY_CAPS,
	type DepCve,
	type HistCommit,
	type HistoricalSignal,
	type HotFile,
} from "./types.js";

/** Matches a CVE id anywhere in free text (case-insensitive). */
const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

/**
 * Secret-shaped tokens redacted out of commit subjects before persistence. We
 * stay conservative: known credential prefixes, private-key headers, and
 * `key=value` secret assignments — never bare hex (that would mask commit shas).
 */
const SECRET_RES: readonly RegExp[] = [
	/AKIA[0-9A-Z]{16}/g, // AWS access key id
	/gh[pousr]_[A-Za-z0-9]{20,}/g, // GitHub PAT / OAuth token
	/xox[baprs]-[A-Za-z0-9-]{10,}/g, // Slack token
	/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, // PEM private key header
	/(?<=\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*)['"]?[^\s'"]{6,}/gi,
];

/** Replace any secret-shaped substring with a fixed marker. */
export function redactSecrets(text: string): string {
	let out = text;
	for (const re of SECRET_RES) out = out.replace(re, "[REDACTED]");
	return out;
}

/** Collect distinct CVE ids (upper-cased) referenced in `text`. */
export function extractCveIds(text: string): string[] {
	const ids = new Set<string>();
	for (const m of text.matchAll(CVE_RE)) ids.add(m[0].toUpperCase());
	return [...ids];
}

function asString(value: unknown): string {
	return typeof value === "string" ? value : "";
}

function asRecord(value: unknown): Record<string, unknown> {
	return value && typeof value === "object"
		? (value as Record<string, unknown>)
		: {};
}

/** Coerce one parsed entry into a `HistCommit`, or `undefined` if it has no sha. */
function coerceCommit(value: unknown): HistCommit | undefined {
	const obj = asRecord(value);
	const sha = asString(obj.sha).trim();
	if (!sha) return undefined;
	const subject = redactSecrets(asString(obj.subject).trim()).slice(
		0,
		HISTORY_CAPS.subjectLen,
	);
	return { sha, date: asString(obj.date).trim(), subject };
}

/** Coerce one parsed entry into a `HotFile`, or `undefined` if it has no path. */
function coerceHotFile(value: unknown): HotFile | undefined {
	const obj = asRecord(value);
	const file = asString(obj.file).trim();
	if (!file) return undefined;

	const seen = new Set<string>();
	const commits: HistCommit[] = [];
	const rawCommits = Array.isArray(obj.commits) ? obj.commits : [];
	for (const raw of rawCommits) {
		const commit = coerceCommit(raw);
		if (!commit || seen.has(commit.sha)) continue;
		seen.add(commit.sha);
		commits.push(commit);
		if (commits.length >= HISTORY_CAPS.commitsPerFile) break;
	}

	// Prefer declared cves, else backfill from the commit subjects.
	const declared = Array.isArray(obj.cves)
		? obj.cves.flatMap((c) => extractCveIds(asString(c)))
		: [];
	const fromSubjects = commits.flatMap((c) => extractCveIds(c.subject));
	const cves = [...new Set([...declared, ...fromSubjects])].slice(
		0,
		HISTORY_CAPS.cvesPerFile,
	);

	const hotFile: HotFile = { file, commits };
	return cves.length > 0 ? { ...hotFile, cves } : hotFile;
}

/** Coerce one parsed entry into a `DepCve`, or `undefined` if under-specified. */
function coerceDepCve(value: unknown): DepCve | undefined {
	const obj = asRecord(value);
	const pkg = asString(obj.package).trim();
	const id = asString(obj.id).trim();
	if (!pkg || !id) return undefined;
	const fixedVersion = asString(obj.fixedVersion).trim();
	const dep: DepCve = {
		package: pkg,
		version: asString(obj.version).trim() || "unknown",
		id,
		severity: asString(obj.severity).trim() || "unknown",
	};
	return fixedVersion ? { ...dep, fixedVersion } : dep;
}

/**
 * Rank hot files by security-commit count (desc), keeping the busiest first,
 * then cap. A file touched by more security/fix commits is a stronger lead.
 */
function rankHotFiles(files: HotFile[]): HotFile[] {
	return [...files]
		.sort((a, b) => b.commits.length - a.commits.length)
		.slice(0, HISTORY_CAPS.hotFiles);
}

/**
 * Coerce an arbitrary parsed value into a valid `HistoricalSignal`. Never
 * throws; unknown/garbage input yields the empty signal.
 */
export function normalizeHistoricalSignal(value: unknown): HistoricalSignal {
	const obj = asRecord(value);
	if (!obj.hotFiles && !obj.depCves) return EMPTY_HISTORICAL_SIGNAL;

	const hotFilesRaw = Array.isArray(obj.hotFiles) ? obj.hotFiles : [];
	const hotFiles = rankHotFiles(
		hotFilesRaw
			.map(coerceHotFile)
			.filter((f): f is HotFile => f !== undefined),
	);

	const depCvesRaw = Array.isArray(obj.depCves) ? obj.depCves : [];
	const seenDep = new Set<string>();
	const depCves: DepCve[] = [];
	for (const raw of depCvesRaw) {
		const dep = coerceDepCve(raw);
		if (!dep) continue;
		const key = `${dep.package}@${dep.version}:${dep.id}`;
		if (seenDep.has(key)) continue;
		seenDep.add(key);
		depCves.push(dep);
		if (depCves.length >= HISTORY_CAPS.depCves) break;
	}

	return { hotFiles, depCves };
}
