// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Dedup-judge prompt construction.
 *
 * Renders the candidate finding plus the accepted-cluster manifest into a single
 * judge prompt that asks the model to cluster by ROOT CAUSE (shared sink /
 * sanitizer-gap / root function) rather than by call-site. The judge returns a
 * `Judgment` (NEW / DUP_BETTER / DUP_SKIP) validated against `judgmentSchema`.
 */

import type { FindingRecord } from "../../job/findings/types.js";
import type { ManifestEntry } from "./manifest.js";

/** Max characters kept per free-text field so the manifest prompt stays bounded. */
const FIELD_CLIP = 360;

/** Trim + collapse whitespace + clip a free-text field for the prompt. */
function clip(value: unknown, max = FIELD_CLIP): string {
	const text = typeof value === "string" ? value : value == null ? "" : String(value);
	const flat = text.replace(/\s+/g, " ").trim();
	return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}

/** file:line of the finding's call-site (root cause may be shared across these). */
function locationOf(f: FindingRecord): string {
	const loc = f.vulnerable_code_location;
	if (!loc || typeof loc !== "object") return "(unknown)";
	const file = typeof loc.file === "string" && loc.file ? loc.file : "(unknown)";
	const line = typeof loc.line === "number" ? loc.line : 0;
	return `${file}:${line}`;
}

/**
 * Compact, root-cause-focused descriptor of a finding for the judge. Call-site
 * (file:line) is labelled explicitly so the model knows two findings may share a
 * root cause despite differing locations; the sanitizer-gap / sink signals live
 * in `missing_defense` / `evidence` / `remediation`.
 */
export function summarizeFinding(f: FindingRecord): string {
	return [
		`Title: ${clip(f.title, 160) || "(untitled)"}`,
		`Category: ${clip(f.category, 40) || "(none)"} | CWE: ${clip(f.cwe, 40) || "(none)"} | OWASP: ${clip(f.owasp_category, 60) || "(none)"}`,
		`Location (call-site): ${locationOf(f)}`,
		`Missing defense (sanitizer/control gap): ${clip(f.missing_defense) || "(none)"}`,
		`Evidence (sink behaviour): ${clip(f.evidence) || "(none)"}`,
		`Remediation (root fix): ${clip(f.remediation) || "(none)"}`,
	].join("\n");
}

const INSTRUCTIONS = `You are a SECURITY FINDING DE-DUPLICATION judge. Decide whether the CANDIDATE
finding shares the SAME ROOT CAUSE as any finding already in the cluster manifest.

ROOT CAUSE = the same underlying weakness: a shared vulnerable sink, the same
missing/broken sanitizer or encoder, or the same root function/helper — EVEN WHEN
the finding surfaces at a DIFFERENT call-site, file, line, route, or parameter.
Two findings reaching the SAME sink or the SAME sanitizer-gap are the SAME root
cause. Do NOT treat a different file:line or category label as automatically
distinct; reason about the underlying weakness, not the surface.

Return exactly one judgment:
- "NEW": a NOVEL root cause not represented in the manifest.
- "DUP_SKIP": shares a root cause with a manifest entry that is an equally-good or
  cleaner example — keep the existing representative.
- "DUP_BETTER": shares a root cause with a manifest entry, but the CANDIDATE is a
  cleaner / stronger / better-evidenced example of that same root cause and should
  replace the representative.

For "DUP_SKIP" and "DUP_BETTER" you MUST set "cluster_id" to the EXACT cluster_id
of the matching manifest entry. For "NEW", omit "cluster_id". Always give a short
"reason".`;

/**
 * Build the full judge prompt for one candidate against the current manifest. An
 * empty manifest is stated explicitly so the model returns NEW without guessing.
 */
export function buildJudgePrompt(
	candidate: FindingRecord,
	manifest: ManifestEntry[],
): string {
	const manifestBlock =
		manifest.length === 0
			? "(empty — the candidate is necessarily NEW)"
			: manifest
					.map((entry) => `[cluster_id=${entry.cluster_id}]\n${summarizeFinding(entry.representative)}`)
					.join("\n\n");

	return [
		INSTRUCTIONS,
		"",
		"=== CANDIDATE FINDING ===",
		summarizeFinding(candidate),
		"",
		`=== ACCEPTED CLUSTER MANIFEST (${manifest.length}) ===`,
		manifestBlock,
	].join("\n");
}
