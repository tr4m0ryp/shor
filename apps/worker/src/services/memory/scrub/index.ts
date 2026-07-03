// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * scrub() — the mandatory pre-ingest filter for the memory store (spec T2
 * guardrails, R4). Pooling knowledge is never pooling credentials: every
 * finding/code text MUST pass through here before any local (011) or global
 * (014) memory write, regardless of pooling mode.
 *
 * Order: secrets first (quarantined behind fingerprint placeholders), then
 * PII redaction over the already-secret-free text, then a containment check
 * that no quarantined raw value survived into the output.
 *
 * FAIL-CLOSED contract: any engine failure yields `{ ok: false, clean: null }`.
 * Callers must not store anything when `ok` is false — there is no clean text
 * to fall back to, by design. This module never logs scanned text or secret
 * material; logs carry counts, rule ids, and entity types only.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { createBuiltinPiiAnalyzer, createPresidioAnalyzer, piiPlaceholder } from "./pii.js";
import { createGitleaksDetector, createTrufflehogDetector, resolveSecretHits } from "./secrets.js";
import {
	ScrubEngineError,
	type PiiEntity,
	type PiiRedactionSummary,
	type ScrubDeps,
	type ScrubResult,
	type SecretHit,
} from "./types.js";

export { createBuiltinPiiAnalyzer, createPresidioAnalyzer, piiPlaceholder } from "./pii.js";
export {
	createGitleaksDetector,
	createTrufflehogDetector,
	quarantinePlaceholder,
	resolveSecretHits,
} from "./secrets.js";
export * from "./types.js";

/** What scrub() accepts: raw text or a JSON-shaped finding record. */
export type Scrubbable = string | Record<string, unknown>;

type LeafPath = ReadonlyArray<string | number>;

interface Leaf {
	path: LeafPath;
	value: string;
}

interface Segment {
	start: number;
	end: number;
}

interface Edit {
	start: number;
	end: number;
	replacement: string;
}

/** Collect every string leaf of a JSON-shaped value, depth-first. */
function collectLeaves(value: unknown, pathAcc: (string | number)[], out: Leaf[], seen: Set<object>): void {
	if (typeof value === "string") {
		out.push({ path: [...pathAcc], value });
		return;
	}
	if (value === null || typeof value !== "object") return;
	if (seen.has(value)) throw new ScrubEngineError("walker", "cyclic input");
	seen.add(value);
	if (Array.isArray(value)) {
		value.forEach((item, i) => collectLeaves(item, [...pathAcc, i], out, seen));
		return;
	}
	for (const [key, item] of Object.entries(value)) collectLeaves(item, [...pathAcc, key], out, seen);
}

/** Join leaves into one scan blob; segments map blob offsets back to leaves. */
function buildBlob(values: readonly string[]): { blob: string; segments: Segment[] } {
	const segments: Segment[] = [];
	let offset = 0;
	const parts: string[] = [];
	for (const value of values) {
		segments.push({ start: offset, end: offset + value.length });
		parts.push(value);
		offset += value.length + 1; // "\n" separator
	}
	return { blob: parts.join("\n"), segments };
}

/** Coalesce overlapping edits (keeping the first replacement) so application is unambiguous. */
function mergeEdits(edits: readonly Edit[]): Edit[] {
	const sorted = [...edits].sort((a, b) => a.start - b.start || b.end - a.end);
	const out: Edit[] = [];
	for (const edit of sorted) {
		const last = out[out.length - 1];
		if (last && edit.start < last.end) {
			last.end = Math.max(last.end, edit.end);
			continue;
		}
		out.push({ ...edit });
	}
	return out;
}

/** Apply blob-coordinate edits to each leaf value (clamped to its segment). */
function applyEditsToLeaves(values: readonly string[], segments: readonly Segment[], edits: readonly Edit[]): string[] {
	return values.map((value, i) => {
		const seg = segments[i];
		if (!seg) return value;
		const local = edits
			.filter((e) => e.start < seg.end && e.end > seg.start)
			.map((e) => ({
				start: Math.max(e.start, seg.start) - seg.start,
				end: Math.min(e.end, seg.end) - seg.start,
				replacement: e.replacement,
			}))
			.sort((a, b) => b.start - a.start);
		let next = value;
		for (const e of local) next = next.slice(0, e.start) + e.replacement + next.slice(e.end);
		return next;
	});
}

/** Write a scrubbed value back into the cloned object at its leaf path. */
function setLeaf(root: Record<string, unknown>, leafPath: LeafPath, value: string): void {
	let node: unknown = root;
	for (let i = 0; i < leafPath.length - 1; i++) {
		node = (node as Record<string | number, unknown>)[leafPath[i] as string];
	}
	const last = leafPath[leafPath.length - 1];
	if (last !== undefined) (node as Record<string | number, unknown>)[last as string] = value;
}

function rebuild<T extends Scrubbable>(input: T, leaves: readonly Leaf[], values: readonly string[]): T {
	if (typeof input === "string") return (values[0] ?? "") as T;
	const clone = structuredClone(input) as Record<string, unknown>;
	leaves.forEach((leaf, i) => setLeaf(clone, leaf.path, values[i] ?? ""));
	return clone as T;
}

/** Count merged PII edits per entity type (placeholders carry the type). */
function summarizePii(edits: readonly Edit[]): PiiRedactionSummary[] {
	const counts = new Map<string, number>();
	for (const edit of edits) {
		const match = /^\[REDACTED-([A-Z0-9_]+)\]$/.exec(edit.replacement);
		const entityType = match?.[1] ?? "UNKNOWN";
		counts.set(entityType, (counts.get(entityType) ?? 0) + 1);
	}
	return [...counts.entries()].map(([entityType, count]) => ({ entityType, count }));
}

/**
 * Production deps from `SHOR_SCRUB_*` env (config seam — callers may thread
 * RuntimeConfig later): gitleaks + trufflehog(verified-only) detectors, and
 * Presidio when `SHOR_SCRUB_PRESIDIO_URL` names the analyzer sidecar.
 */
export function createDefaultScrubDeps(
	env: NodeJS.ProcessEnv = process.env,
	logger?: ActivityLogger,
): ScrubDeps {
	const gitleaksBin = env["SHOR_SCRUB_GITLEAKS_BIN"]?.trim();
	const trufflehogBin = env["SHOR_SCRUB_TRUFFLEHOG_BIN"]?.trim();
	const presidioUrl = env["SHOR_SCRUB_PRESIDIO_URL"]?.trim();
	const piiAnalyzers = presidioUrl
		? [createBuiltinPiiAnalyzer(), createPresidioAnalyzer(presidioUrl)]
		: [createBuiltinPiiAnalyzer()];
	return {
		secretDetectors: [
			createGitleaksDetector(gitleaksBin ? { bin: gitleaksBin } : {}),
			createTrufflehogDetector(trufflehogBin ? { bin: trufflehogBin } : {}),
		],
		piiAnalyzers,
		piiEngine: presidioUrl ? "presidio+builtin" : "builtin",
		logger,
	};
}

/**
 * Scrub raw text or a finding record. Returns `{ ok: true, clean, ... }` with
 * secrets quarantined and PII redacted, or `{ ok: false, clean: null }` when
 * any engine could not run — in which case the input is unsafe to store.
 */
export async function scrub<T extends Scrubbable>(input: T, deps: ScrubDeps): Promise<ScrubResult<T>> {
	try {
		const leaves: Leaf[] = [];
		if (typeof input === "string") leaves.push({ path: [], value: input });
		else collectLeaves(input, [], leaves, new Set());
		const values = leaves.map((l) => l.value);
		const pass1 = buildBlob(values);
		if (pass1.blob.length === 0) {
			return { ok: true, clean: rebuild(input, leaves, values), quarantined: [], pii: [], piiEngine: deps.piiEngine };
		}

		// Pass 1: secrets -> quarantine. Detector throw = fail closed.
		const hits: SecretHit[] = [];
		for (const detect of deps.secretDetectors) hits.push(...(await detect(pass1.blob)));
		const resolution = resolveSecretHits(pass1.blob, hits);
		const afterSecrets = applyEditsToLeaves(values, pass1.segments, mergeEdits(resolution.edits));

		// Pass 2: PII over the already-secret-free text. Analyzer throw = fail closed.
		const pass2 = buildBlob(afterSecrets);
		const entities: PiiEntity[] = [];
		for (const analyze of deps.piiAnalyzers) entities.push(...(await analyze(pass2.blob)));
		const piiEdits = mergeEdits(
			entities
				.filter((e) => e.start >= 0 && e.end > e.start && e.end <= pass2.blob.length)
				.map((e) => ({ start: e.start, end: e.end, replacement: piiPlaceholder(e.entityType) })),
		);
		const finalValues = applyEditsToLeaves(afterSecrets, pass2.segments, piiEdits);

		// Containment check: no quarantined raw value may survive into the output.
		const finalBlob = finalValues.join("\n");
		for (const raw of resolution.rawValues) {
			if (raw.length > 0 && finalBlob.includes(raw)) {
				throw new ScrubEngineError("containment", "a quarantined value survived redaction");
			}
		}

		const pii = summarizePii(piiEdits);
		deps.logger?.info("scrub: complete", {
			quarantinedSecrets: resolution.quarantined.length,
			piiRedactions: pii.reduce((sum, p) => sum + p.count, 0),
			piiEngine: deps.piiEngine,
		});
		return { ok: true, clean: rebuild(input, leaves, finalValues), quarantined: resolution.quarantined, pii, piiEngine: deps.piiEngine };
	} catch (err) {
		const reason = err instanceof Error ? err.message : String(err);
		deps.logger?.error("scrub: FAILED CLOSED — input is unsafe to store", { reason });
		return { ok: false, clean: null, reason, quarantined: [] };
	}
}
