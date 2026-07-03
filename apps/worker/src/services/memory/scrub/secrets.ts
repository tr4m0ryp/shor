// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Secret detection + quarantine for the scrub stage.
 *
 * Wraps the same CLI tools the vuln agents use as skills
 * (skills/static-analysis/secrets/*): gitleaks as the fast regex/entropy pass
 * and trufflehog restricted to VERIFIED hits (`--only-verified`) to cut noise
 * per the spec. Both are repo/dir scanners, not stdin filters, so the text is
 * scanned via a private 0600 temp file that is always deleted afterwards.
 *
 * Hygiene invariants (ADR-050 — values header-only, never logged):
 * - gitleaks runs with `--redact`; only line/column spans leave its report.
 * - trufflehog raw values transit process memory just long enough to excise
 *   them; only a sha256 fingerprint + masked preview survive.
 * - Nothing in this module logs or returns raw secret material.
 * - Any engine failure or unlocatable hit throws {@link ScrubEngineError},
 *   which the orchestrator turns into a fail-closed result.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import {
	ScrubEngineError,
	type QuarantinedSecret,
	type SecretDetector,
	type SecretHit,
	type TextSpan,
} from "./types.js";

const execFileP = promisify(execFile);
const MAX_BUFFER = 32 * 1024 * 1024;

export interface CliDetectorOptions {
	/** Binary name/path override (defaults to the tool on PATH). */
	bin?: string | undefined;
	timeoutMs?: number | undefined;
}

/** Truncated error text — keeps tool stderr from smuggling content into logs. */
function brief(err: unknown): string {
	const msg = err instanceof Error ? err.message : String(err);
	return msg.length > 200 ? `${msg.slice(0, 200)}…` : msg;
}

/** Run `fn` against the text staged in a private temp dir; always clean up. */
async function withTempTextFile<T>(
	text: string,
	fn: (dir: string) => Promise<T>,
): Promise<T> {
	const dir = await mkdtemp(path.join(tmpdir(), "shor-scrub-"));
	try {
		await writeFile(path.join(dir, "scrub-input.txt"), text, { mode: 0o600 });
		return await fn(dir);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}

/** Byte offset of each line start, for line/column -> absolute span conversion. */
function lineStartOffsets(text: string): number[] {
	const starts = [0];
	for (let i = 0; i < text.length; i++) {
		if (text[i] === "\n") starts.push(i + 1);
	}
	return starts;
}

/** Convert a 1-based line/column (inclusive) range to a `[start, end)` span. */
function spanFromLineCols(
	lineStarts: number[],
	textLength: number,
	startLine: unknown,
	startColumn: unknown,
	endLine: unknown,
	endColumn: unknown,
): TextSpan | null {
	if (
		typeof startLine !== "number" ||
		typeof startColumn !== "number" ||
		typeof endLine !== "number" ||
		typeof endColumn !== "number"
	) {
		return null;
	}
	const startBase = lineStarts[startLine - 1];
	const endBase = lineStarts[endLine - 1];
	if (startBase === undefined || endBase === undefined) return null;
	const start = Math.max(0, startBase + startColumn - 1);
	const end = Math.min(textLength, endBase + endColumn);
	return end > start ? { start, end } : null;
}

/**
 * gitleaks fast pass (`gitleaks dir`, v8.19+ syntax — matches the worker
 * image; see skills/static-analysis/secrets/gitleaks). The report is written
 * with `--redact`, so only rule ids and line/column spans are read back —
 * the raw value is excised from the original text by offset alone.
 */
export function createGitleaksDetector(opts: CliDetectorOptions = {}): SecretDetector {
	const bin = opts.bin ?? "gitleaks";
	const timeout = opts.timeoutMs ?? 60_000;
	return async (text) =>
		withTempTextFile(text, async (dir) => {
			const report = path.join(dir, "gitleaks-report.json");
			try {
				await execFileP(
					bin,
					["dir", dir, "--report-format", "json", "--report-path", report, "--redact", "--exit-code", "0", "--no-banner"],
					{ timeout, maxBuffer: MAX_BUFFER },
				);
			} catch (err) {
				throw new ScrubEngineError("gitleaks", brief(err));
			}
			let leaks: unknown;
			try {
				leaks = JSON.parse(await readFile(report, "utf8"));
			} catch (err) {
				// No/unreadable report = we cannot prove the text is clean: fail closed.
				throw new ScrubEngineError("gitleaks", `report unreadable: ${brief(err)}`);
			}
			if (!Array.isArray(leaks)) throw new ScrubEngineError("gitleaks", "report is not an array");
			const lineStarts = lineStartOffsets(text);
			return leaks.map((leak): SecretHit => {
				const row = leak as Record<string, unknown>;
				const span = spanFromLineCols(
					lineStarts,
					text.length,
					row["StartLine"],
					row["StartColumn"],
					row["EndLine"],
					row["EndColumn"],
				);
				// A leak we cannot locate would otherwise pass through: fail closed.
				if (!span) throw new ScrubEngineError("gitleaks", "leak row without a resolvable span");
				return { source: "gitleaks", ruleId: String(row["RuleID"] ?? "unknown"), span };
			});
		});
}

/**
 * trufflehog verified-only pass. NOTE: verification makes live outbound calls
 * to the issuing providers — that egress must be allowed where this runs.
 * Findings arrive as JSONL on stdout; `Raw`/`RawV2` are consumed in-memory to
 * excise every occurrence, then dropped.
 */
export function createTrufflehogDetector(opts: CliDetectorOptions = {}): SecretDetector {
	const bin = opts.bin ?? "trufflehog";
	const timeout = opts.timeoutMs ?? 120_000;
	return async (text) =>
		withTempTextFile(text, async (dir) => {
			let stdout: string;
			try {
				({ stdout } = await execFileP(
					bin,
					["filesystem", dir, "--only-verified", "--json", "--no-update"],
					{ timeout, maxBuffer: MAX_BUFFER },
				));
			} catch (err) {
				throw new ScrubEngineError("trufflehog", brief(err));
			}
			const hits: SecretHit[] = [];
			for (const line of stdout.split("\n")) {
				const trimmed = line.trim();
				if (!trimmed.startsWith("{")) continue;
				let row: Record<string, unknown>;
				try {
					row = JSON.parse(trimmed) as Record<string, unknown>;
				} catch {
					continue; // interleaved non-JSON noise, not a finding
				}
				// Finding rows carry SourceMetadata + DetectorName; anything else is a log line.
				if (row["SourceMetadata"] === undefined || typeof row["DetectorName"] !== "string") continue;
				const ruleId = row["DetectorName"];
				let located = false;
				for (const key of ["Raw", "RawV2"] as const) {
					const value = row[key];
					if (typeof value === "string" && value.length > 0) {
						hits.push({ source: "trufflehog", ruleId, value });
						located = true;
					}
				}
				// A verified secret we cannot excise must not pass through: fail closed.
				if (!located) throw new ScrubEngineError("trufflehog", `finding without raw locator (${ruleId})`);
			}
			return hits;
		});
}

/** Masked preview for the quarantine record — never reversible. */
function maskValue(raw: string): string {
	if (raw.length < 12) return "****";
	return `${raw.slice(0, 4)}****(len=${raw.length})`;
}

function fingerprintOf(raw: string): string {
	return createHash("sha256").update(raw, "utf8").digest("hex").slice(0, 16);
}

/** Downstream text references the quarantine record by fingerprint only. */
export function quarantinePlaceholder(fingerprint: string): string {
	return `[QUARANTINED-SECRET:${fingerprint}]`;
}

export interface SecretEdit extends TextSpan {
	replacement: string;
}

export interface SecretResolution {
	edits: SecretEdit[];
	quarantined: QuarantinedSecret[];
	/**
	 * Raw values, kept ONLY for the orchestrator's final containment check
	 * (asserting nothing survived into the clean output). Dropped after; never
	 * logged or emitted.
	 */
	rawValues: string[];
}

/**
 * Resolve detector hits into text edits + non-retrievable quarantine records.
 * Pure. A hit with neither a value nor a span is unlocatable and throws
 * (fail closed) rather than passing the secret through.
 */
export function resolveSecretHits(text: string, hits: readonly SecretHit[]): SecretResolution {
	const edits: SecretEdit[] = [];
	const byFingerprint = new Map<string, QuarantinedSecret>();
	const rawValues = new Set<string>();
	const record = (hit: SecretHit, raw: string, occurrences: number): void => {
		const fingerprint = fingerprintOf(raw);
		const existing = byFingerprint.get(fingerprint);
		if (existing) {
			existing.occurrences += occurrences;
		} else {
			byFingerprint.set(fingerprint, {
				source: hit.source,
				ruleId: hit.ruleId,
				fingerprint,
				preview: maskValue(raw),
				occurrences,
			});
		}
		rawValues.add(raw);
	};
	for (const hit of hits) {
		if (hit.value !== undefined && hit.value.length > 0) {
			const raw = hit.value;
			const replacement = quarantinePlaceholder(fingerprintOf(raw));
			let occurrences = 0;
			for (let i = text.indexOf(raw); i >= 0; i = text.indexOf(raw, i + raw.length)) {
				edits.push({ start: i, end: i + raw.length, replacement });
				occurrences += 1;
			}
			// occurrences can be 0 (tool decoded/derived the value); still record it —
			// the containment check downstream guards against a missed literal.
			record(hit, raw, occurrences);
		} else if (hit.span && hit.span.end > hit.span.start) {
			const start = Math.max(0, hit.span.start);
			const end = Math.min(text.length, hit.span.end);
			if (end <= start) throw new ScrubEngineError("resolver", "span outside scanned text");
			const raw = text.slice(start, end);
			edits.push({ start, end, replacement: quarantinePlaceholder(fingerprintOf(raw)) });
			record(hit, raw, 1);
		} else {
			throw new ScrubEngineError("resolver", `unlocatable hit from ${hit.source}:${hit.ruleId}`);
		}
	}
	return { edits, quarantined: [...byFingerprint.values()], rawValues: [...rawValues] };
}
