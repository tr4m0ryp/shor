// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Severity / confidence / reachability calibration (spec T10 + T13).
 *
 * Pure, synchronous functions: given a finding, the threat model, and an optional
 * LLM grade, recompute its labels from REAL risk. Threat impact sets the severity
 * baseline; confirmation/evidence raises it; low reachability, low attacker
 * control, and low likelihood CAP it (never drop — capping only lowers the label,
 * the finding is always returned). All re-labelling is signal-gated: with no
 * threat match, no grade, and no oracle disposition, the patch is the finding's
 * own labels (identity), so the no-deliverables path is unchanged.
 */

import type { FindingGrade } from "../../ai/structured/index.js";
import type {
	FindingConfidence,
	FindingRecord,
	FindingSeverity,
	Reachability,
} from "../../job/findings/types.js";
import {
	type ImpactLevel,
	impactOrdinal,
	likelihoodOrdinal,
	type Threat,
	type ThreatActor,
} from "../threat-model/index.js";

// === Severity ladder (info=0 .. critical=4) ===

const SEV_BY_ORD: FindingSeverity[] = ["info", "low", "medium", "high", "critical"];
const SEV_ORD: Record<string, number> = {
	info: 0,
	low: 1,
	medium: 2,
	high: 3,
	critical: 4,
};
const LOW = 1;
const MEDIUM = 2;
const HIGH = 3;
const CRITICAL = 4;

function clampSev(ord: number): FindingSeverity {
	return SEV_BY_ORD[Math.max(0, Math.min(CRITICAL, ord))] ?? "info";
}

/** Threat impact -> baseline severity ordinal (existential collapses onto critical). */
function impactToSevOrd(impact: ImpactLevel): number {
	return Math.min(CRITICAL, impactOrdinal(impact)); // low=1 .. critical=4, existential(5)->4
}

/** Attacker-control rank from the threat actor: remote-unauth (4) down to insider (1). */
function attackerControl(actor: ThreatActor): number {
	switch (actor) {
		case "remote_unauth":
			return 4;
		case "remote_auth":
			return 3;
		case "adjacent_network":
		case "supply_chain":
			return 2;
		default:
			return 1; // local_user / local_admin / insider
	}
}

// === Threat matching ===

const STOPWORDS = new Set([
	"the", "and", "for", "with", "via", "from", "into", "that", "this", "are",
	"was", "can", "not", "you", "your", "code", "issue", "vuln", "input", "data",
	"user", "request", "value", "field", "based", "when", "where", "which",
]);

/** Category -> extra keywords so a finding aligns with its structural threat. */
const CATEGORY_KEYWORDS: Record<string, string[]> = {
	xss: ["xss", "cross", "script", "scripting", "dom", "reflected", "stored"],
	injection: ["injection", "inject", "sql", "sqli", "command", "rce", "query"],
	auth: ["auth", "authentication", "session", "token", "login", "credential", "password"],
	ssrf: ["ssrf", "server", "forgery", "fetch", "outbound", "metadata"],
	authz: ["authz", "authorization", "access", "idor", "privilege", "role", "tenant"],
};

function tokenize(text: string): Set<string> {
	const out = new Set<string>();
	for (const tok of text.toLowerCase().split(/[^a-z0-9]+/)) {
		if (tok.length >= 3 && !STOPWORDS.has(tok)) out.add(tok);
	}
	return out;
}

function findingTokens(finding: FindingRecord): Set<string> {
	const loc = finding.vulnerable_code_location?.file ?? "";
	const base = tokenize(
		`${finding.title} ${finding.category} ${finding.cwe} ${loc} ${finding.missing_defense ?? ""}`,
	);
	for (const kw of CATEGORY_KEYWORDS[finding.category] ?? []) base.add(kw);
	return base;
}

function threatTokens(threat: Threat): Set<string> {
	return tokenize(`${threat.surface} ${threat.asset} ${threat.threat} ${threat.controls}`);
}

/** Best matched threat plus the overlap strength (0 = no shared signal). */
export interface ThreatMatch {
	threat: Threat;
	strength: number;
}

/**
 * Map a finding to the threat whose surface/asset best matches, by token overlap
 * (category keywords weighted x2). Returns the strongest match; `strength` is 0
 * when nothing overlapped, letting the caller decline to reset the baseline from
 * a non-match while still recording ownership.
 */
export function matchThreat(finding: FindingRecord, threats: Threat[]): ThreatMatch | null {
	if (threats.length === 0) return null;
	const fTokens = findingTokens(finding);
	const catKeywords = new Set(CATEGORY_KEYWORDS[finding.category] ?? []);
	let best: ThreatMatch | null = null;
	for (const threat of threats) {
		const tTokens = threatTokens(threat);
		let strength = 0;
		for (const tok of fTokens) {
			if (tTokens.has(tok)) strength += catKeywords.has(tok) ? 2 : 1;
		}
		if (!best || strength > best.strength) best = { threat, strength };
	}
	return best;
}

// === Label calibration ===

function heuristicEvidenceScore(finding: FindingRecord): 0 | 1 | 2 {
	const loc = finding.vulnerable_code_location;
	const hasLoc = !!loc?.file && typeof loc.line === "number" && loc.line > 0;
	const hasRepro =
		(Array.isArray(finding.repro_steps) && finding.repro_steps.length > 0) ||
		(typeof finding.safe_poc === "string" && finding.safe_poc.trim().length > 20);
	const evLen = (finding.evidence ?? "").trim().length;
	if (hasLoc && hasRepro && evLen > 80) return 2;
	if (hasLoc || hasRepro || evLen > 120) return 1;
	return 0;
}

function coerceReachability(value: string | undefined): Reachability | undefined {
	if (value === "REACHABLE" || value === "HARNESS_ONLY" || value === "UNCLEAR") return value;
	return undefined;
}

/**
 * Reachability of the vulnerable code, from the strongest available signal:
 * an oracle live-exploit (REACHABLE) > the LLM grade > the finding's prior value.
 * `undefined` when nothing establishes it (so the caller leaves it untouched).
 */
function calibrateReachability(
	finding: FindingRecord,
	grade: FindingGrade | undefined,
): Reachability | undefined {
	if (finding.oracle_disposition === "exploited") return "REACHABLE";
	if (grade) return coerceReachability(grade.reachability) ?? "UNCLEAR";
	return finding.reachability;
}

/**
 * Confidence from evidence quality + oracle disposition. Oracle-confirmed exploit
 * (or a collection-proven finding) is `confirmed`; otherwise strong evidence is
 * `firm` and anything thinner is `tentative`. Never invents `unverified` (that is
 * the gate's out-of-scope label, applied before emission).
 */
function calibrateConfidence(
	finding: FindingRecord,
	evidenceScore: 0 | 1 | 2,
	hasGrade: boolean,
): FindingConfidence {
	if (finding.oracle_disposition === "exploited") return "confirmed";
	if (finding.confidence === "confirmed") return "confirmed";
	if (finding.oracle_disposition === "blocked") return "tentative";
	if (hasGrade) return evidenceScore >= 2 ? "firm" : "tentative";
	return finding.confidence;
}

/**
 * Final severity = threat impact baseline, RAISED by confirmation and CAPPED by
 * low reachability / low attacker control / low likelihood / thin evidence. Caps
 * only lower the label; the finding is never dropped. A proven (`confirmed`,
 * reachable) finding is floored at its prior severity so calibration can sharpen
 * but never silently bury a live exploit.
 */
function calibrateSeverity(
	finding: FindingRecord,
	match: ThreatMatch | null,
	reachability: Reachability | undefined,
	confidence: FindingConfidence,
	evidenceScore: 0 | 1 | 2,
	graded: boolean,
): FindingSeverity {
	const existing = SEV_ORD[finding.severity] ?? LOW;
	const matched = match && match.strength > 0 ? match : null;
	const base = matched ? impactToSevOrd(matched.threat.impact) : existing;

	let sev = base;
	if (confidence === "confirmed") sev = Math.min(base + 1, CRITICAL);
	else if (graded && evidenceScore === 0) sev = Math.max(base - 1, LOW);

	if (reachability === "HARNESS_ONLY") sev = Math.min(sev, MEDIUM);
	else if (reachability === "UNCLEAR") sev = Math.min(sev, HIGH);

	if (matched) {
		if (attackerControl(matched.threat.actor) <= 1) sev = Math.min(sev, HIGH);
		if (confidence !== "confirmed" && likelihoodOrdinal(matched.threat.likelihood) <= 2) {
			sev = Math.min(sev, HIGH);
		}
	}

	// Proven + reachable findings are never calibrated below their prior severity.
	if (confidence === "confirmed" && reachability !== "HARNESS_ONLY") {
		sev = Math.max(sev, existing);
	}
	return clampSev(sev);
}

/** The recomputed labels applied to a finding by {@link calibrateFinding}. */
export interface FindingPatch {
	confidence: FindingConfidence;
	severity: FindingSeverity;
	reachability?: Reachability;
	threat_id?: string;
}

/**
 * Recompute one finding's labels from its grade + the threat model. Pure and
 * total: it always returns a patch (never throws, never signals removal). With no
 * threat match, no grade, and no oracle signal, the patch equals the finding's
 * current labels — an identity no-op.
 */
export function calibrateFinding(
	finding: FindingRecord,
	threats: Threat[],
	grade: FindingGrade | undefined,
): FindingPatch {
	const evidenceScore: 0 | 1 | 2 = grade ? grade.evidence_score : heuristicEvidenceScore(finding);
	const match = matchThreat(finding, threats);
	const reachability = calibrateReachability(finding, grade);
	const confidence = calibrateConfidence(finding, evidenceScore, !!grade);
	const graded = !!grade || finding.oracle_disposition !== undefined;
	const severity = calibrateSeverity(finding, match, reachability, confidence, evidenceScore, graded);

	const patch: FindingPatch = { confidence, severity };
	if (reachability !== undefined) patch.reachability = reachability;
	if (match && match.strength > 0) patch.threat_id = match.threat.id;
	return patch;
}
