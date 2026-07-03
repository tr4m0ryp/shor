// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * De-slop rewrite — PURE, deterministic (spec T14, F11).
 *
 * Turns a BOILERPLATE remediation (the mapper's "Apply the missing defense: X. See
 * the attack-surface deliverable ..." template, detected by `remediation-guard`) into
 * a finding-SPECIFIC fix line — anchored to the finding's own `file:line`, its route,
 * its sink, and its `missing_defense`.
 *
 * NON-NEGOTIABLE — NO FABRICATION. Every specific token in the rewrite is lifted from
 * the finding's OWN fields (location / evidence / repro_steps / safe_poc / title /
 * missing_defense). The class-standard fix verb keyed by category/CWE asserts no
 * target-specific fact. When the finding carries no concrete anchor to specialize
 * with, the rewrite is DECLINED (returns null) — the original stands, flagged, never
 * replaced by invention.
 */

import { isBoilerplateRemediation } from "../../job/findings/remediation-guard.js";
import type { FindingRecord } from "../../job/findings/types.js";

/** Class-standard fix verb per category — asserts no target-specific fact. */
const CLASS_DEFENSE: Record<string, string> = {
	injection:
		"use parameterized queries / prepared statements and never concatenate untrusted input into the statement",
	xss: "context-encode the untrusted value on output and apply a strict Content-Security-Policy",
	auth: "enforce the missing authentication check and validate the credential/token before trusting the request",
	authz: "enforce a server-side authorization check that the caller owns or may access the requested resource",
	ssrf: "validate and allowlist the outbound host and block requests to internal / link-local address ranges",
	logic: "enforce the business-rule invariant server-side and re-validate the state transition on every step",
	"misconfig-web": "correct the insecure setting and set the appropriate security header / cookie flag",
};

/** Pull the specific defense out of `missing_defense`, or the boilerplate's own `<X>`. */
function extractDefense(f: FindingRecord): string {
	const md = typeof f.missing_defense === "string" ? f.missing_defense.trim() : "";
	if (md && !isBoilerplateRemediation(md)) return md.replace(/\.+$/, "");
	const rem = typeof f.remediation === "string" ? f.remediation : "";
	const m = rem.match(/apply the (?:missing|context-correct)[^:]*:?\s*(.+?)(?:\.\s*see the attack-surface|\.\s*$|$)/is);
	const cap = m?.[1]?.trim();
	return cap && !/^see the attack-surface/i.test(cap) ? cap.replace(/\.+$/, "") : "";
}

/** The finding's own text corpus — the ONLY place route/sink tokens may come from. */
function evidenceCorpus(f: FindingRecord): string {
	return [
		typeof f.evidence === "string" ? f.evidence : "",
		typeof f.safe_poc === "string" ? f.safe_poc : "",
		Array.isArray(f.repro_steps) ? f.repro_steps.join("\n") : "",
		typeof f.title === "string" ? f.title : "",
	].join("\n");
}

const ROUTE_METHOD_RE = /\b(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\/[^\s"'`)]+)/;
const ROUTE_PATH_RE = /(?<![\w.])(\/[A-Za-z0-9_][A-Za-z0-9_\-/.{}:]*)/;
/** An identifier immediately calling `(` — a plausible sink; filtered by a stoplist. */
const SINK_RE = /\b([A-Za-z_$][\w$]*(?:(?:->|::|\.)[A-Za-z_$][\w$]*)*)\s*\(/g;
const SINK_STOPLIST = new Set([
	"if", "for", "while", "switch", "function", "return", "catch", "console", "log",
	"require", "import", "the", "a", "is", "was", "get", "set", "and", "or", "not",
]);

/** Route lifted from the finding's own evidence — METHOD+path preferred. `` when none. */
function extractRoute(corpus: string, fileLoc: string): string {
	const m = corpus.match(ROUTE_METHOD_RE);
	if (m) return `${m[1]} ${m[2]}`;
	const p = corpus.match(ROUTE_PATH_RE);
	const path = p?.[1];
	// Reject a match that is really the vulnerable FILE path (already the location anchor).
	if (path && path.length > 1 && !fileLoc.includes(path) && !path.includes(fileLoc)) return path;
	return "";
}

/** Sink identifier lifted from the finding's own evidence prose. `` when none clean. */
function extractSink(corpus: string): string {
	SINK_RE.lastIndex = 0;
	for (let m = SINK_RE.exec(corpus); m; m = SINK_RE.exec(corpus)) {
		const id = m[1];
		if (!id) continue;
		const leaf = id.split(/->|::|\./).pop() ?? id;
		if (leaf.length < 3 || leaf.length > 40) continue;
		if (SINK_STOPLIST.has(leaf.toLowerCase())) continue;
		return id;
	}
	return "";
}

/** Location anchor `file:line` (line only when > 0). `` when no file recorded. */
function locationAnchor(f: FindingRecord): string {
	const file = f.vulnerable_code_location?.file?.trim();
	if (!file) return "";
	const line = f.vulnerable_code_location?.line;
	return typeof line === "number" && line > 0 ? `${file}:${line}` : file;
}

/**
 * Rewrite a boilerplate remediation into a finding-specific one, or return `null` when
 * it is NOT boilerplate (nothing to do) or cannot be specialized without invention.
 * Pure — reads only `f`'s own fields.
 */
export function rewriteRemediation(f: FindingRecord): string | null {
	if (!isBoilerplateRemediation(f.remediation)) return null;

	const location = locationAnchor(f);
	const corpus = evidenceCorpus(f);
	const route = extractRoute(corpus, location);
	const sink = extractSink(corpus);
	const defense = extractDefense(f);
	const classDefense = CLASS_DEFENSE[String(f.category)] ?? "";

	// A concrete anchor is required: no invention when the finding gives us nothing.
	const hasAnchor = Boolean(location || route || sink || defense);
	if (!hasAnchor) return null;

	const where = location
		? `In \`${location}\``
		: route
			? `On the \`${route}\` endpoint`
			: "At the vulnerable sink";
	const fix = defense || classDefense || "apply the context-correct defense for this weakness class";

	let out = `${where}, ${fix}.`;
	if (route && !where.includes(route)) out += ` This affects the \`${route}\` route.`;
	if (sink && !out.includes(sink)) out += ` The untrusted value reaches the \`${sink}\` sink.`;
	return out;
}
