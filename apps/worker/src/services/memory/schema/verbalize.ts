// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Verbalize a finding into the retrieval representation (spec T3, R3).
 *
 * Output: a labeled Vul-RAG doc (Vector A) with a contextual metadata prefix,
 * the minimal vulnerable code block (Vector B, late-chunked), and structured
 * columns. This module is PURE — it neither scrubs nor embeds; the write path
 * (`../write/persist.ts`) scrubs the output BEFORE any embed/store. Raw JSON is
 * never embedded: retrieval is on semantics.
 */

import type {
	CodeChunkOptions,
	FindingLike,
	FindingMetadata,
	VerbalizedFinding,
} from "./types.js";

/** Labels in the fixed order the verbalized doc renders them (spec T3). */
export const DOC_LABELS = [
	"VULNERABILITY",
	"ENDPOINT",
	"DATA FLOW",
	"WHAT THE CODE DOES",
	"ROOT CAUSE",
	"IMPACT",
	"REMEDIATION",
] as const;

const NA = "n/a";
const DEFAULT_CODE_CHARS = 2000;

/** First non-empty, trimmed string among candidate top-level keys, else null. */
function pick(finding: FindingLike, keys: readonly string[]): string | null {
	for (const key of keys) {
		const value = finding[key];
		if (typeof value === "string" && value.trim() !== "") return value.trim();
	}
	return null;
}

/** Read a string off a nested object property (e.g. `data_flow.source`). */
function pickNested(
	finding: FindingLike,
	parent: string,
	child: string,
): string | null {
	const obj = finding[parent];
	if (obj && typeof obj === "object" && !Array.isArray(obj)) {
		const value = (obj as Record<string, unknown>)[child];
		if (typeof value === "string" && value.trim() !== "") return value.trim();
	}
	return null;
}

/** The HTTP method + route, e.g. "POST /login", or a bare route, or null. */
function extractRoute(finding: FindingLike): string | null {
	const route =
		pick(finding, ["route", "endpoint", "path", "url"]) ??
		pickNested(finding, "data_flow", "route");
	if (!route) return null;
	// If the route already carries a method (e.g. "POST /x"), keep it as-is.
	if (/^[A-Z]+\s+\S/.test(route)) return route;
	const method = pick(finding, ["method", "http_method", "verb"]);
	return method ? `${method.toUpperCase()} ${route}` : route;
}

/** The taint source, from a flat key or a nested `data_flow.source`. */
function extractSource(finding: FindingLike): string | null {
	return (
		pick(finding, ["source", "taint_source", "source_endpoint"]) ??
		pickNested(finding, "data_flow", "source")
	);
}

/** The taint sink, from a flat key or a nested `data_flow.sink`. */
function extractSink(finding: FindingLike): string | null {
	return (
		pick(finding, ["sink", "taint_sink", "vulnerable_sink"]) ??
		pickNested(finding, "data_flow", "sink")
	);
}

/** A `component@version` string when the finding names a vulnerable component. */
function extractComponentVer(finding: FindingLike): string | null {
	const combined = pick(finding, [
		"component_version",
		"componentVer",
		"component_ver",
	]);
	if (combined) return combined;
	const component = pick(finding, ["component", "package", "dependency"]);
	if (!component) return null;
	const version = pick(finding, ["version", "component_version_number"]);
	return version ? `${component}@${version}` : component;
}

/** Extract the SQL-prefilter columns from a finding. */
export function extractMetadata(finding: FindingLike): FindingMetadata {
	return {
		cwe: pick(finding, ["cwe"]),
		vulnClass: pick(finding, ["vuln_class", "category", "weakness"]),
		severity: pick(finding, ["severity"]),
		route: extractRoute(finding),
		source: extractSource(finding),
		sink: extractSink(finding),
		componentVer: extractComponentVer(finding),
		confidence: pick(finding, ["confidence"]),
	};
}

/**
 * Contextual-retrieval metadata prefix (R3: a metadata prefix cut failed
 * retrievals ~49%). One compact line of the highest-signal filters, prepended
 * to the verbalized doc before embedding.
 */
export function metadataPrefix(
	meta: FindingMetadata,
	route: string | null,
): string {
	const parts = [
		`CWE=${meta.cwe ?? NA}`,
		`class=${meta.vulnClass ?? NA}`,
		`severity=${meta.severity ?? NA}`,
		`route=${route ?? NA}`,
	];
	return `[${parts.join(" | ")}]`;
}

/** Value for the VULNERABILITY label — title/class plus CWE and severity. */
function vulnerabilityLine(
	finding: FindingLike,
	meta: FindingMetadata,
): string {
	const name =
		pick(finding, ["title", "vuln_class", "category"]) ??
		"Unclassified weakness";
	const cwe = meta.cwe ?? NA;
	const severity = meta.severity ?? NA;
	return `${name} (${cwe}, severity=${severity})`;
}

/** Value for DATA FLOW — "<source> -> <sink>" with n/a placeholders. */
function dataFlowLine(meta: FindingMetadata): string {
	return `${meta.source ?? NA} -> ${meta.sink ?? NA}`;
}

/** Longhand description of the vulnerable behavior, from the richest field. */
function whatTheCodeDoes(finding: FindingLike): string {
	return (
		pick(finding, [
			"what_the_code_does",
			"code_summary",
			"description",
			"evidence",
		]) ?? NA
	);
}

/** Root-cause narrative — the dedicated field, else the missing defense. */
function rootCause(finding: FindingLike): string {
	return pick(finding, ["root_cause", "missing_defense"]) ?? NA;
}

/** Impact narrative — the dedicated field, else a severity-derived default. */
function impact(finding: FindingLike, meta: FindingMetadata): string {
	const explicit = pick(finding, ["impact", "business_impact"]);
	if (explicit) return explicit;
	return meta.severity
		? `Potential ${meta.severity}-severity impact if exploited.`
		: NA;
}

/** Assemble the labeled doc body (without the metadata prefix). */
function renderDoc(
	finding: FindingLike,
	meta: FindingMetadata,
	route: string | null,
): string {
	const values: Record<(typeof DOC_LABELS)[number], string> = {
		VULNERABILITY: vulnerabilityLine(finding, meta),
		ENDPOINT: route ?? NA,
		"DATA FLOW": dataFlowLine(meta),
		"WHAT THE CODE DOES": whatTheCodeDoes(finding),
		"ROOT CAUSE": rootCause(finding),
		IMPACT: impact(finding, meta),
		REMEDIATION: pick(finding, ["remediation", "fix"]) ?? NA,
	};
	return DOC_LABELS.map((label) => `${label}: ${values[label]}`).join("\n");
}

/**
 * Late-chunk a code block to a soft character budget while preserving the
 * context immediately around the vulnerable sink. When `focusHint` is present
 * and found, a window is centered on it; otherwise the head of the block is
 * kept. Whole blocks under the budget pass through unchanged (the "keep
 * surrounding context" intent — do not pre-shred into tiny windows).
 */
export function lateChunkCode(
	code: string,
	opts: CodeChunkOptions = {},
): string {
	const maxChars = opts.maxChars ?? DEFAULT_CODE_CHARS;
	const trimmed = code.replace(/\s+$/g, "");
	if (trimmed.length <= maxChars) return trimmed;
	const focus = opts.focusHint?.trim();
	const at = focus ? trimmed.indexOf(focus) : -1;
	if (at < 0) return `${trimmed.slice(0, maxChars)}\n/* ...truncated... */`;
	const half = Math.floor(maxChars / 2);
	const start = Math.max(0, at - half);
	const end = Math.min(trimmed.length, start + maxChars);
	const head = start > 0 ? "/* ...truncated... */\n" : "";
	const tail = end < trimmed.length ? "\n/* ...truncated... */" : "";
	return `${head}${trimmed.slice(start, end)}${tail}`;
}

/**
 * Extract the minimal vulnerable code block (Vector B) from a finding, with a
 * `// file:line` context header when a location is known. Returns null when the
 * finding carries no code snippet — no code vector is then written.
 */
export function extractCodeBlock(finding: FindingLike): string | null {
	const snippet = pick(finding, [
		"code_snippet",
		"snippet",
		"vulnerable_code",
		"code",
		"source_snippet",
	]);
	if (!snippet) return null;
	const loc = finding.vulnerable_code_location;
	const file = typeof loc?.file === "string" ? loc.file : null;
	const line = typeof loc?.line === "number" ? loc.line : null;
	const header = file ? `// ${file}${line !== null ? `:${line}` : ""}\n` : "";
	const focusHint = extractSink(finding);
	return `${header}${lateChunkCode(snippet, { focusHint })}`;
}

/**
 * Render a finding into its full verbalized representation. Pure and total:
 * any finding (even a near-empty one) yields all seven labels — absent fields
 * render as `n/a`. The caller MUST scrub `text` and `codeBlock` before embed.
 */
export function verbalize(finding: FindingLike): VerbalizedFinding {
	const meta = extractMetadata(finding);
	const route = meta.route;
	const prefix = metadataPrefix(meta, route);
	const doc = renderDoc(finding, meta, route);
	return {
		metadataPrefix: prefix,
		doc,
		text: `${prefix}\n\n${doc}`,
		codeBlock: extractCodeBlock(finding),
		metadata: meta,
	};
}
