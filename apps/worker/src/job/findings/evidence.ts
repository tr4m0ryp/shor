// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Parse the per-category exploitation evidence markdown into a per-VULN-ID
 * disposition (`exploited` / `blocked`) + prose map, used to promote a queued
 * analysis hypothesis to a live-confirmed finding.
 *
 * The exploit prompts ask for two top-level sections:
 *   `## Successfully Exploited Vulnerabilities`        → disposition `exploited`
 *   `## Potential Vulnerabilities (Validation Blocked)`→ disposition `blocked`
 * with findings as `### <VULN-ID>: <title>` blocks beneath them.
 *
 * In practice the agents (and the firm-retry rewrite pass) drift from that exact
 * shape — alternate section names ("Confirmed Vulnerabilities …"), zero-padding
 * differences in IDs, extra numbering, etc. A strict match silently dropped every
 * finding to `queued` → `firm` (the "nothing is ever confirmed" regression). This
 * parser is therefore deliberately tolerant:
 *   - heading classification accepts success/blocked SYNONYMS (see
 *     {@link dispositionForHeading});
 *   - under an UNRECOGNIZED section heading, each block is classified by strong
 *     in-prose markers ({@link classifyByContent}) rather than dropped;
 *   - VULN-IDs are canonicalized ({@link canonicalVulnId}) so case/zero-padding
 *     differences still match, with a trailing-number fallback ({@link lookupEvidence}).
 * Conservatism is preserved: an entry filed under an explicit BLOCKED section
 * stays `blocked` even if its prose is hopeful, so this never manufactures a
 * false `confirmed`.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { FindingCategory } from "./types.js";

/** Evidence filenames keyed by category (mirrors DELIVERABLE_FILENAMES). */
const EVIDENCE_FILES: Record<FindingCategory, string> = {
	injection: "injection_exploitation_evidence.md",
	xss: "xss_exploitation_evidence.md",
	auth: "auth_exploitation_evidence.md",
	ssrf: "ssrf_exploitation_evidence.md",
	authz: "authz_exploitation_evidence.md",
};

export interface EvidenceEntry {
	disposition: "exploited" | "blocked";
	text: string;
}

type Disposition = "exploited" | "blocked";

/**
 * Classify a `## ` section heading into a disposition. Blocked/potential buckets
 * are tested FIRST so "Confirmed but blocked"-style headings stay `blocked` (a
 * conservative bias — we never want to manufacture a false confirmation). Returns
 * `undefined` for an unrelated/drifted heading; such sections are not dropped —
 * their entries fall back to content-based classification.
 */
function dispositionForHeading(heading: string): Disposition | undefined {
	const h = heading.toLowerCase();
	if (
		/validation blocked|potential vulnerab|attempted exploitation|\bblocked\b|not exploit|unconfirmed|could not|unsuccessful/.test(
			h,
		)
	) {
		return "blocked";
	}
	if (/successfully exploited|confirmed|exploited|proven|verified live|live[- ]confirmed/.test(h)) {
		return "exploited";
	}
	return undefined;
}

/**
 * Strong, success-only markers used to classify a `### <ID>:` block that sits
 * under an UNRECOGNIZED section heading (heading drift). Deliberately specific to
 * REALIZED exploitation — "Proof of Impact" is the exploited-template section
 * header (the blocked template uses "Expected Impact"), so it is a reliable
 * positive signal and won't fire on hypothetical "would-be" prose.
 */
const CONFIRMED_MARKERS =
	/confirmed live|live[- ]confirmed|successfully exploited|exploitation succeeded|exploit succeeded|proof of impact|account takeover achieved|extracted (?:the |a |gcp |aws |an? )?(?:access[- ]?token|credential|secret|service account)/i;

/** Markers that a probe was actively stopped — used only under drifted headings. */
const BLOCKED_MARKERS =
	/validation blocked|blocked by|intercepted by|waf|rate[- ]?limit|\b429\b|\b401\b|\b403\b|forbidden|could not exploit|unable to exploit|not exploitable|attempt(?:ed)? .*failed/i;

/** Best-effort disposition from block prose, for entries under a drifted heading. */
function classifyByContent(text: string): Disposition {
	if (CONFIRMED_MARKERS.test(text)) return "exploited";
	if (BLOCKED_MARKERS.test(text)) return "blocked";
	// In the evidence file but no clear signal: treat as attempted-but-unconfirmed
	// (`blocked`) rather than `exploited`. Never a silent false confirmation.
	return "blocked";
}

/**
 * Canonicalize a VULN-ID for tolerant matching: uppercase, trim, drop leading
 * zeros in the numeric suffix. `auth-vuln-09` and `AUTH-VULN-9` both canonicalize
 * to `AUTH-VULN-9`.
 */
export function canonicalVulnId(id: string): string {
	return id.trim().toUpperCase().replace(/-0+(\d)/g, "-$1");
}

/** Extract a `<VULN-ID>` from a `### ID: title` line, or undefined. */
function vulnIdFromSubheading(line: string): string | undefined {
	// Strip the leading hashes and any list numbering ("### 1. AUTH-VULN-01: …").
	const body = line.replace(/^#{2,}\s*/, "").replace(/^\d+[.)]\s*/, "");
	// Prefer an explicit `<PREFIX>-VULN-<n>` token anywhere in the heading.
	const tok = body.match(/([A-Za-z]{2,12}-VULN-\d+)/i);
	if (tok?.[1]) return tok[1];
	// Fall back to the first token before a separator (legacy shape).
	const m = body.match(/^([A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)*)\s*[:—-]/);
	return m?.[1];
}

/**
 * Parse one evidence markdown body into a per-VULN-ID disposition + prose map,
 * keyed by {@link canonicalVulnId}. `exploited` beats `blocked` if an ID appears
 * under both.
 */
export function parseEvidenceMarkdown(body: string): Map<string, EvidenceEntry> {
	const result = new Map<string, EvidenceEntry>();
	const lines = body.split(/\r?\n/);

	let section: Disposition | undefined;
	let sectionRecognized = false;
	let currentId: string | undefined;
	let buffer: string[] = [];

	const flush = (): void => {
		if (currentId) {
			const text = buffer.join("\n").trim();
			// A recognized section heading is authoritative; under a drifted heading
			// fall back to in-prose classification so confirmations are not lost.
			const disposition: Disposition = sectionRecognized
				? (section as Disposition)
				: classifyByContent(text);
			const key = canonicalVulnId(currentId);
			const existing = result.get(key);
			if (
				!existing ||
				(existing.disposition === "blocked" && disposition === "exploited")
			) {
				result.set(key, { disposition, text });
			}
		}
		currentId = undefined;
		buffer = [];
	};

	for (const line of lines) {
		if (line.startsWith("## ")) {
			flush();
			section = dispositionForHeading(line.slice(3).trim());
			sectionRecognized = section !== undefined;
			continue;
		}
		if (line.startsWith("### ")) {
			flush();
			currentId = vulnIdFromSubheading(line);
			buffer = [];
			continue;
		}
		if (currentId) buffer.push(line);
	}
	flush();
	return result;
}

/**
 * Look up the evidence entry for a queue VULN-ID, tolerating ID drift: exact
 * canonical match first, then a trailing-number fallback (safe because every
 * evidence map is per-category, so the numeric suffix is unique within it).
 */
export function lookupEvidence(
	map: Map<string, EvidenceEntry>,
	vulnId: string,
): EvidenceEntry | undefined {
	const canon = canonicalVulnId(vulnId);
	const direct = map.get(canon);
	if (direct) return direct;
	const num = canon.match(/(\d+)$/)?.[1];
	if (!num) return undefined;
	for (const [key, entry] of map) {
		if (key.match(/(\d+)$/)?.[1] === num) return entry;
	}
	return undefined;
}

/**
 * Read and parse the evidence markdown for one category. Missing/unreadable
 * files yield an empty map (best-effort). Keys are canonical VULN-IDs.
 */
export function readEvidence(
	deliverablesPath: string,
	category: FindingCategory,
	logger: ActivityLogger,
): Map<string, EvidenceEntry> {
	const filePath = path.join(deliverablesPath, EVIDENCE_FILES[category]);
	try {
		if (!fs.existsSync(filePath)) return new Map();
		return parseEvidenceMarkdown(fs.readFileSync(filePath, "utf8"));
	} catch (err) {
		logger.warn("Failed to read evidence markdown; skipping", {
			filePath,
			error: err instanceof Error ? err.message : String(err),
		});
		return new Map();
	}
}
