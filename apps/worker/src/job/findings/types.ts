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
export type FindingConfidence = "confirmed" | "firm" | "tentative";
export type FindingStatus = "new" | "open" | "fixed" | "regressed";

/** file:line location for code findings (§6.1). */
export interface VulnerableCodeLocation {
	file: string;
	line: number;
}

/** Structured finding record — mirrors LAUNCH-SPEC §6.1. */
export interface FindingRecord {
	id: string;
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
	/** `exploited` if the evidence MD lists it as proven; `queued` otherwise. */
	disposition: "exploited" | "blocked" | "queued";
	/** Exploitation-evidence prose for this VULN-ID, when present. */
	evidenceText: string;
}

/** Raw queue wrapper shape: `{ vulnerabilities: [...] }`. */
export interface RawQueue {
	vulnerabilities?: unknown[];
	[key: string]: unknown;
}
