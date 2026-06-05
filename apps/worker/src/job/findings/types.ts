// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Local types for the findings-emission step (ADR-051 → dashboard contract).
 *
 * `FindingRecord` mirrors the Shor web `FindingRecord` (LAUNCH-SPEC §6.1)
 * verbatim — the worker and the web sink share this exact shape. We redeclare
 * it here rather than import across the app boundary: the worker package does
 * not depend on `@shor/web`.
 */

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
/**
 * §6.1 confidence ladder, plus one worker-internal rung. `unverified` is used
 * ONLY for `unverified_out_of_scope` findings (see {@link VulnDisposition}): it
 * means "not seen in analyzed source, not live-confirmed". Such records are
 * routed to the manual-review appendix and EXCLUDED from the emitted set, so
 * this value is never POSTed to the dashboard sink.
 */
export type FindingConfidence =
	| "confirmed"
	| "firm"
	| "tentative"
	| "unverified";

/**
 * Human-readable explanation of WHY a finding is not `confirmed`. Always
 * empty for `exploited` dispositions; populated for every other outcome so the
 * dashboard and attack surface can surface a specific failure reason rather than
 * a bare "firm" label.
 *
 * Categories (maps to `VulnDisposition`):
 *   - `blocked_waf`       – live probe intercepted by WAF / security control
 *   - `blocked_auth`      – endpoint requires authentication we did not hold
 *   - `blocked_ratelimit` – rate-limited during exploitation attempt
 *   - `blocked_internal`  – endpoint not externally reachable (internal/VPN only)
 *   - `blocked`           – blocked, specific reason not identifiable from evidence
 *   - `unproven`          – queued hypothesis; no live validation evidence produced
 *   - `excluded`          – enforcing tier not in analyzed source (unverified_out_of_scope)
 */
export type ValidationFailureReason =
	| "blocked_waf"
	| "blocked_auth"
	| "blocked_ratelimit"
	| "blocked_internal"
	| "blocked"
	| "unproven"
	| "excluded";
export type FindingStatus = "new" | "open" | "fixed" | "regressed";

/**
 * Disposition of a normalized vuln as it flows through collection.
 *   - `exploited` — proven live (evidence markdown); never gated out.
 *   - `blocked`   — attempted but validation/defense blocked it.
 *   - `queued`    — a hypothesis from the analysis queue, not yet exploited.
 *   - `unverified_out_of_scope` (T3, gating) — the tier that would enforce this
 *     finding's control was NOT in the analyzed source AND it was not
 *     live-confirmed. Terminal: excluded from the emitted findings and routed
 *     to the manual-review appendix. Distinct from `tentative` (weak-but-seen).
 *   - `unverified_screen_rejected` — the adversarial screen agent refuted this
 *     hypothesis before exploitation (recorded in `{category}_screen_rejected.json`).
 *     Treated identically to `unverified_out_of_scope` for emission: excluded from
 *     the emitted set and the attack surface, routed to the manual-review appendix
 *     for audit. Distinct so the appendix can label WHY it was set aside.
 */
export type VulnDisposition =
	| "exploited"
	| "blocked"
	| "queued"
	| "unverified_out_of_scope"
	| "unverified_screen_rejected";

/** file:line location for code findings (§6.1). */
export interface VulnerableCodeLocation {
	file: string;
	line: number;
}

/** Structured finding record — mirrors LAUNCH-SPEC §6.1. */
export interface FindingRecord {
	id: string;
	/**
	 * Human-readable explanation of why this finding is not `confirmed`. Empty
	 * for `exploited` (confirmed) dispositions. Populated for `blocked`,
	 * `queued`, and `unverified_out_of_scope`. Use the `ValidationFailureReason`
	 * enum values but stored as a plain string for forward-compatibility.
	 * Example: "Blocked — WAF / security control intercepted the probe".
	 */
	validation_note: string;
	/**
	 * Human-readable finding title (e.g. "Stored XSS", "Token Management Issue").
	 * Always synthesized at mapping time from the weakness type so the dashboard
	 * never falls back to the bare category ("xss"/"auth"); the Sinas improver may
	 * later overwrite it with a sharper, location-specific title.
	 */
	title: string;
	category: string;
	cwe: string;
	owasp_category: string;
	severity: FindingSeverity;
	confidence: FindingConfidence;
	evidence: string;
	safe_poc: string;
	repro_steps: string[];
	vulnerable_code_location: VulnerableCodeLocation;
	missing_defense: string;
	remediation: string;
	status: FindingStatus;
	fingerprint: string;
	partialFingerprints: Record<string, string>;
	/**
	 * Collection-time disposition (forwarded from the source vuln). Present so the
	 * coverage gate can route `unverified_out_of_scope` records to the manual-
	 * review appendix; emitted findings carry `exploited`/`blocked`/`queued`. Not
	 * part of the web §6.1 surface — carried via the index signature below.
	 */
	disposition?: VulnDisposition;
	[key: string]: unknown;
}

/** Body POSTed to the findings sink per the shared contract. */
export interface FindingsSinkPayload {
	findings: FindingRecord[];
	attackSurface?: Record<string, unknown>;
	// `running` is used for incremental mid-run posts (findings accrue in the DB
	// as agents finish); the sink only transitions the scan on completed/failed.
	status: "completed" | "failed" | "running";
}

/** The five vulnerability categories the pipeline produces queues for. */
export type FindingCategory = "injection" | "xss" | "auth" | "ssrf" | "authz";

/**
 * A normalized vulnerability drawn from a per-category exploitation queue,
 * optionally enriched with the live disposition from the evidence markdown.
 * Field names vary across queues; we keep the raw object plus the extracted,
 * category-agnostic fields the mapper needs.
 */
export interface NormalizedVuln {
	category: FindingCategory;
	id: string;
	raw: Record<string, unknown>;
	/**
	 * `exploited` if the evidence MD lists it as proven; `queued` otherwise. The
	 * coverage gate may later set `unverified_out_of_scope` (see {@link VulnDisposition}).
	 */
	disposition: VulnDisposition;
	/** Exploitation-evidence prose for this VULN-ID, when present. */
	evidenceText: string;
}

/** Raw queue wrapper shape: `{ vulnerabilities: [...] }`. */
export interface RawQueue {
	vulnerabilities?: unknown[];
	[key: string]: unknown;
}
