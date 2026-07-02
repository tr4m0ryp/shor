// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-category metadata + field resolvers for mapping a raw queue entry to a
 * `FindingRecord`. Queue field names differ per vulnerability class (see the
 * vuln prompts' `exploitation_queue_format`); this module centralizes the
 * category-specific extraction so the mapper stays generic.
 */

import type { FindingCategory } from "./types.js";

export interface CategoryMeta {
	/** Default CWE when the entry carries no explicit `cwe`/`cwe_id`. */
	defaultCwe: string;
	/** OWASP Top 10 (2021) category for this class. */
	owasp: string;
	/** Candidate keys (in priority order) holding a `file:line` location. */
	locationKeys: string[];
	/** Candidate keys holding the missing-defense / root-cause text. */
	defenseKeys: string[];
	/** Candidate keys holding the endpoint/source for the location fallback. */
	endpointKeys: string[];
	/** Candidate keys holding a witness/PoC payload. */
	witnessKeys: string[];
	/** Candidate keys holding the per-entry severity, if any. */
	severityKeys: string[];
}

export const CATEGORY_META: Record<FindingCategory, CategoryMeta> = {
	injection: {
		defaultCwe: "CWE-89",
		owasp: "A03:2021-Injection",
		locationKeys: ["sink_call", "source", "vulnerable_code_location"],
		defenseKeys: ["mismatch_reason", "sanitization_observed"],
		endpointKeys: ["path", "source"],
		witnessKeys: ["witness_payload"],
		severityKeys: ["severity_score"],
	},
	xss: {
		defaultCwe: "CWE-79",
		owasp: "A03:2021-Injection",
		locationKeys: ["sink_function", "source_detail", "source"],
		defenseKeys: ["mismatch_reason", "encoding_observed"],
		endpointKeys: ["source", "path"],
		witnessKeys: ["witness_payload"],
		severityKeys: ["severity_score"],
	},
	auth: {
		defaultCwe: "CWE-287",
		owasp: "A07:2021-Identification and Authentication Failures",
		locationKeys: ["vulnerable_code_location"],
		defenseKeys: ["missing_defense", "exploitation_hypothesis"],
		endpointKeys: ["source_endpoint"],
		witnessKeys: ["suggested_exploit_technique"],
		severityKeys: ["severity_score"],
	},
	ssrf: {
		defaultCwe: "CWE-918",
		owasp: "A10:2021-Server-Side Request Forgery (SSRF)",
		locationKeys: ["vulnerable_code_location"],
		defenseKeys: ["missing_defense", "exploitation_hypothesis"],
		endpointKeys: ["source_endpoint", "vulnerable_parameter"],
		witnessKeys: ["suggested_exploit_technique"],
		severityKeys: ["severity_score"],
	},
	authz: {
		defaultCwe: "CWE-862",
		owasp: "A01:2021-Broken Access Control",
		locationKeys: ["vulnerable_code_location"],
		defenseKeys: ["guard_evidence", "reason"],
		endpointKeys: ["endpoint"],
		witnessKeys: ["minimal_witness"],
		severityKeys: ["severity_score"],
	},
	logic: {
		defaultCwe: "CWE-840",
		owasp: "A04:2021-Insecure Design",
		locationKeys: ["vulnerable_code_location"],
		defenseKeys: ["broken_invariant", "reason"],
		endpointKeys: ["endpoint", "source_endpoint"],
		witnessKeys: ["minimal_witness"],
		severityKeys: ["severity_score"],
	},
	"misconfig-web": {
		defaultCwe: "CWE-16",
		owasp: "A05:2021-Security Misconfiguration",
		locationKeys: ["vulnerable_code_location", "config_location"],
		defenseKeys: ["misconfiguration_detail", "reason"],
		endpointKeys: ["endpoint", "source_endpoint"],
		witnessKeys: ["minimal_witness"],
		severityKeys: ["severity_score"],
	},
};

/** First non-empty string value among `keys` on `raw`, else "". */
export function firstString(
	raw: Record<string, unknown>,
	keys: string[],
): string {
	for (const key of keys) {
		const v = raw[key];
		if (typeof v === "string" && v.trim() !== "") return v.trim();
	}
	return "";
}

/** Explicit CWE on the entry (`cwe` or `cwe_id`), else "". */
export function explicitCwe(raw: Record<string, unknown>): string {
	return firstString(raw, ["cwe", "cwe_id"]);
}
