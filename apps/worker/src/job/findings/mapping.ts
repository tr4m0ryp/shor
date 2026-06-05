// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Map a normalized queue entry (+ optional exploitation evidence) into a
 * `FindingRecord` (LAUNCH-SPEC §6.1). Best-effort: a missing field becomes an
 * empty string / sentinel rather than dropping the finding — partial findings
 * beat none.
 *
 * `fingerprint` is the load-bearing stable diff key (ADR-031):
 *   sha256(category + cwe + normalized_location + evidence_signature).
 */

import { createHash } from "node:crypto";
import { CATEGORY_META, explicitCwe, firstString } from "./category-meta.js";
import type {
	FindingCategory,
	FindingConfidence,
	FindingRecord,
	FindingSeverity,
	NormalizedVuln,
	VulnerableCodeLocation,
} from "./types.js";

/** Readable class label per category (the dashboard shows the short code badge). */
const CLASS_LABEL: Record<FindingCategory, string> = {
	injection: "Injection",
	xss: "XSS",
	auth: "Authentication",
	ssrf: "SSRF",
	authz: "Authorization",
};

/**
 * Humanize a raw `vulnerability_type` token ("Login_Flow_Logic" → "Login Flow
 * Logic", "DOM-based" → "DOM-based"). Underscores become spaces; an all-lowercase
 * word is capitalized, but existing caps (DOM, JWT, IDOR) are preserved.
 */
function humanizeType(vt: string): string {
	return vt
		.replace(/_+/g, " ")
		.replace(/\s+/g, " ")
		.trim()
		.split(" ")
		.map((w) => (w && /[a-z]/.test(w) && w === w.toLowerCase() ? w.charAt(0).toUpperCase() + w.slice(1) : w))
		.join(" ");
}

/**
 * Expand terse weakness-type codes that are meaningless on their own ("Horizontal"
 * / "Vertical" authz, etc.) into a self-describing phrase. Keyed by the lowercased
 * raw `vulnerability_type`; anything not listed is humanized as-is.
 */
const TYPE_EXPANSION: Record<string, string> = {
	horizontal: "Horizontal Access Control / IDOR",
	vertical: "Vertical Privilege Escalation",
	context_workflow: "Workflow Authorization Bypass",
	service_discovery: "Internal Service Discovery",
};

/**
 * Synthesize a descriptive finding title from the weakness class + type so a
 * finding is never displayed as the bare category. XSS reads best as "<type>
 * XSS"; other classes get the humanized type, suffixed with the class label when
 * the type alone is not self-describing.
 */
function synthTitle(category: FindingCategory, vulnerabilityType: string): string {
	const label = CLASS_LABEL[category] ?? category.toUpperCase();
	const expanded = TYPE_EXPANSION[vulnerabilityType.toLowerCase().trim()] ?? vulnerabilityType;
	const h = humanizeType(expanded);
	if (!h) return category === "xss" ? "Cross-Site Scripting (XSS)" : `${label} weakness`;
	if (category === "xss") return /xss|scripting/i.test(h) ? h : `${h} XSS`;
	if (/injection|ssrf|xss|scripting|authoriz|authentic|idor|traversal/i.test(h)) return h;
	return `${h} (${label})`;
}

/** Parse a `path/to/file.ts:123` token into `{ file, line }`. */
function parseLocation(loc: string): VulnerableCodeLocation {
	if (!loc) return { file: "", line: 0 };
	// Take the last `:<digits>` as the line; everything before is the file.
	const m = loc.match(/^(.*?):(\d+)(?:\D.*)?$/);
	if (m?.[1] !== undefined && m[2] !== undefined) {
		return { file: m[1].trim(), line: Number(m[2]) };
	}
	return { file: loc.trim(), line: 0 };
}

const SEVERITY_VALUES: readonly FindingSeverity[] = [
	"critical",
	"high",
	"medium",
	"low",
	"info",
];

/** Parse a free-form severity string to the §6.1 enum, or null if unrecognized. */
function parseSeverity(value: string): FindingSeverity | null {
	const v = value.toLowerCase().trim();
	if ((SEVERITY_VALUES as string[]).includes(v)) return v as FindingSeverity;
	if (v === "informational" || v === "information") return "info";
	return null;
}

/**
 * Infer severity by vulnerability class, escalated when the finding was actually
 * exploited live. Used ONLY when the analysis queue carried no explicit severity.
 * Most vuln-agent queues (xss/auth/ssrf/authz) omit a severity field entirely —
 * without this fallback every such finding read "medium", masking real
 * critical/high issues (only the injection queue declares `severity_score`).
 */
function inferSeverity(
	category: FindingCategory,
	disposition: NormalizedVuln["disposition"],
): FindingSeverity {
	// [baseline, exploited] severity per class.
	const table: Record<FindingCategory, readonly [FindingSeverity, FindingSeverity]> = {
		injection: ["high", "critical"],
		auth: ["high", "critical"],
		ssrf: ["medium", "high"],
		xss: ["medium", "high"],
		authz: ["medium", "high"],
	};
	const [base, escalated] = table[category];
	return disposition === "exploited" ? escalated : base;
}

/**
 * Derive a human-readable explanation of why the finding is not `confirmed`.
 * Pattern-matches the exploitation evidence prose for specific blocking reasons;
 * falls back to a generic label per disposition. Empty for `exploited` findings.
 */
function synthesizeValidationNote(
	disposition: NormalizedVuln["disposition"],
	evidenceText: string,
): string {
	if (disposition === "exploited") return "";
	if (disposition === "unverified_out_of_scope") {
		return "Excluded — enforcing tier not in analyzed source; could not be verified from this scan";
	}
	if (disposition === "unverified_screen_rejected") {
		const reason = evidenceText.trim();
		return reason
			? `Refuted by adversarial screen — ${reason}`
			: "Refuted — the adversarial screen rejected this hypothesis before exploitation; not a confirmed finding";
	}
	if (disposition === "blocked") {
		const e = evidenceText.toLowerCase();
		if (/waf|cloudflare|akamai|imperva|block(ed)?\s+by\s+(waf|security|firewall)/.test(e)) {
			return "Blocked — WAF / security control intercepted the probe";
		}
		if (/rate.?limit|429|too many requests|throttl/.test(e)) {
			return "Blocked — rate-limited during exploitation attempt";
		}
		if (/internal|vpn|tailscale|private.?network|not externally|requires.*(vpn|internal)/.test(e)) {
			return "Blocked — endpoint requires internal network access (not externally reachable)";
		}
		if (/401|403|unauthorized|forbidden|authentication required|session required|login required/.test(e)) {
			return "Blocked — requires authenticated session not available during testing";
		}
		return "Blocked — security control prevented exploitation; finding unconfirmed";
	}
	// disposition === "queued": no evidence entry for this finding
	return "Unproven — no live validation evidence produced; finding remains a code-analysis hypothesis";
}

/** Map a queue confidence + disposition to the §6.1 confidence enum. */
function normalizeConfidence(
	value: string,
	disposition: NormalizedVuln["disposition"],
): FindingConfidence {
	if (disposition === "exploited") return "confirmed";
	// Out-of-scope + unconfirmed: the enforcing tier was never in the analyzed
	// source and nothing live-confirmed it. A screen-rejected hypothesis was
	// actively REFUTED by the adversarial screen. Neither may read as firm/tentative
	// (i.e. "as if seen") — give them the dedicated `unverified` rung. Both are
	// excluded from the emitted set and routed to the manual-review appendix.
	if (
		disposition === "unverified_out_of_scope" ||
		disposition === "unverified_screen_rejected"
	) {
		return "unverified";
	}
	const v = value.toLowerCase().trim();
	if (v === "high") return "firm";
	if (v === "med" || v === "medium") return "firm";
	return "tentative";
}

/** Status for a freshly-emitted finding (always `new`; see below). */
function statusFor(): FindingRecord["status"] {
	// Every emitted finding is reported fresh; the web side computes the diff
	// lifecycle (open/fixed/regressed) against prior scans via the fingerprint.
	return "new";
}

/**
 * Stable diff fingerprint (ADR-031): sha256 over category + cwe + normalized
 * location + an evidence signature. Lowercased + whitespace-collapsed so cosmetic
 * churn does not change the key.
 */
function computeFingerprint(
	category: string,
	cwe: string,
	location: VulnerableCodeLocation,
	evidenceSignature: string,
): string {
	const norm = (s: string): string => s.toLowerCase().replace(/\s+/g, " ").trim();
	const locKey = `${norm(location.file)}:${location.line}`;
	const material = [norm(category), norm(cwe), locKey, norm(evidenceSignature)].join(
		" ",
	);
	return createHash("sha256").update(material, "utf8").digest("hex");
}

/** Map one normalized vuln into a §6.1 FindingRecord. */
export function toFindingRecord(vuln: NormalizedVuln): FindingRecord {
	const meta = CATEGORY_META[vuln.category];
	const raw = vuln.raw;

	const cwe = explicitCwe(raw) || meta.defaultCwe;
	const locText =
		firstString(raw, meta.locationKeys) || firstString(raw, meta.endpointKeys);
	const location = parseLocation(locText);
	// Raw value drives the fingerprint (stable identity); the OUTPUT field gets a
	// non-empty fallback so the dashboard never shows a blank.
	const missingDefenseRaw = firstString(raw, meta.defenseKeys);
	const missingDefense = missingDefenseRaw || "Not specified — see analysis deliverable";
	const witness = firstString(raw, meta.witnessKeys);

	// Evidence: prefer the live exploitation prose; fall back to a synthesized
	// summary from the queue entry so the field is never empty.
	const queueSummary = [
		firstString(raw, ["vulnerability_type"]),
		firstString(raw, meta.endpointKeys),
		missingDefenseRaw,
		firstString(raw, ["notes"]),
	]
		.filter((s) => s !== "")
		.join(" — ");
	const evidence = vuln.evidenceText.trim() || queueSummary || `${vuln.category} finding — see analysis deliverable`;

	// Prefer an explicit severity from the queue (under any of the field names the
	// prompts use); otherwise infer from class + whether it was exploited. Never
	// blanket-default to "medium" — that masked the real distribution.
	const explicitSeverity = parseSeverity(
		firstString(raw, [...meta.severityKeys, "severity", "severity_rating", "risk", "severity_band"]),
	);
	const severity = explicitSeverity ?? inferSeverity(vuln.category, vuln.disposition);
	const confidence = normalizeConfidence(
		firstString(raw, ["confidence"]),
		vuln.disposition,
	);

	const reproStep = firstString(raw, meta.endpointKeys);
	const fingerprint = computeFingerprint(
		vuln.category,
		cwe,
		location,
		// signature: source/sink + missing defense gives a stable identity even
		// before live evidence exists (raw value — the display fallback must not
		// shift the fingerprint).
		`${locText}|${missingDefenseRaw}|${firstString(raw, ["vulnerability_type"])}`,
	);

	const vulnerabilityType = firstString(raw, ["vulnerability_type"]);
	const validation_note = synthesizeValidationNote(vuln.disposition, vuln.evidenceText);
	return {
		id: vuln.id,
		title: synthTitle(vuln.category, vulnerabilityType),
		category: vuln.category,
		cwe,
		owasp_category: meta.owasp,
		severity,
		confidence,
		evidence,
		safe_poc: witness || "See exploitation evidence deliverable",
		repro_steps: reproStep ? [reproStep] : [],
		vulnerable_code_location: location,
		missing_defense: missingDefense,
		remediation: missingDefenseRaw
			? `Apply the missing defense: ${missingDefenseRaw}. See the attack-surface deliverable for the context-correct fix prompt.`
			: `Apply the context-correct ${vuln.category} defense; see the attack-surface deliverable for the fix prompt.`,
		status: statusFor(),
		fingerprint,
		partialFingerprints: {
			"locationCwe/v1": computeFingerprint(vuln.category, cwe, location, ""),
		},
		validation_note,
		// Forward-compatible: keep raw queue fields + disposition for the sink.
		disposition: vuln.disposition,
		vulnerability_type: vulnerabilityType,
		externally_exploitable: raw.externally_exploitable === true,
	};
}

/** Map a batch, skipping nothing (each entry yields one record). */
export function toFindingRecords(vulns: NormalizedVuln[]): FindingRecord[] {
	return vulns.map(toFindingRecord);
}
