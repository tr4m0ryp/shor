// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Evidence-parser drift-tolerance regression tests.
 *
 * Core defect this guards against: the disposition pipeline derives `confirmed`
 * solely by matching a queue VULN-ID to an "exploited" entry in the per-category
 * exploitation-evidence markdown. A STRICT match (exact section heading + exact
 * `### <ID>:` + exact queue ID) silently dropped every live-confirmed finding to
 * `queued` → `firm` whenever the agents' output drifted from the template — which
 * produced runs with 0 `confirmed` despite many live confirmations. These tests
 * lock in the tolerant behavior: alternate "Confirmed" headings, zero-padded /
 * case-variant IDs, and content-marker classification under a drifted heading all
 * resolve to `exploited`, while an explicit BLOCKED section never manufactures a
 * false confirmation.
 */

import { describe, expect, it } from "vitest";
import {
	canonicalVulnId,
	lookupEvidence,
	parseEvidenceMarkdown,
} from "./evidence.js";

describe("canonicalVulnId", () => {
	it("uppercases and strips leading zeros in the numeric suffix", () => {
		expect(canonicalVulnId("auth-vuln-007")).toBe("AUTH-VULN-7");
		expect(canonicalVulnId(" authz-vuln-12 ")).toBe("AUTHZ-VULN-12");
		expect(canonicalVulnId("INJ-VULN-01")).toBe("INJ-VULN-1");
	});
});

describe("parseEvidenceMarkdown — canonical, template-compliant input", () => {
	it("classifies the two standard sections", () => {
		const md = `# Evidence
## Successfully Exploited Vulnerabilities
### INJ-VULN-01: sqli
**Proof of Impact:** dumped the users table.
## Potential Vulnerabilities (Validation Blocked)
### INJ-VULN-02: blind
Blocked by WAF.
`;
		const m = parseEvidenceMarkdown(md);
		expect(m.get("INJ-VULN-1")?.disposition).toBe("exploited");
		expect(m.get("INJ-VULN-2")?.disposition).toBe("blocked");
	});
});

describe("parseEvidenceMarkdown — heading / ID drift", () => {
	it("treats an alternate 'Confirmed' section heading as exploited", () => {
		const md = `## Confirmed Vulnerabilities (live)
### AUTHZ-VULN-012: alg none
**Proof of Impact:** Confirmed live: forged JWT returns 200 on /Users/me.
`;
		// Zero-padded id canonicalizes to AUTHZ-VULN-12.
		expect(parseEvidenceMarkdown(md).get("AUTHZ-VULN-12")?.disposition).toBe(
			"exploited",
		);
	});

	it("never promotes an explicit BLOCKED section even with hopeful prose", () => {
		const md = `## Potential Vulnerabilities (Validation Blocked)
### AUTH-VULN-03: reset poisoning
**Current Blocker:** WAF intercepted. If removed it would allow takeover.
`;
		expect(parseEvidenceMarkdown(md).get("AUTH-VULN-3")?.disposition).toBe(
			"blocked",
		);
	});

	it("classifies by content under an unrecognized heading", () => {
		const md = `## Exploitation Results
### SSRF-VULN-01: metadata
Extracted the GCP access token via OOB listener.
### SSRF-VULN-02: internal probe
Attempted probe failed; endpoint returned 403 forbidden.
### XSS-VULN-04: stored
SSRF confirmed and the alert(1) fired in the browser.
`;
		const m = parseEvidenceMarkdown(md);
		expect(m.get("SSRF-VULN-1")?.disposition).toBe("exploited");
		expect(m.get("SSRF-VULN-2")?.disposition).toBe("blocked");
		expect(m.get("XSS-VULN-4")?.disposition).toBe("exploited");
	});

	it("lets exploited win when an ID appears under both sections", () => {
		const md = `## Potential Vulnerabilities (Validation Blocked)
### AUTH-VULN-05: replay
Blocked initially.
## Successfully Exploited Vulnerabilities
### AUTH-VULN-05: replay
**Proof of Impact:** Successfully exploited on retry.
`;
		expect(parseEvidenceMarkdown(md).get("AUTH-VULN-5")?.disposition).toBe(
			"exploited",
		);
	});
});

describe("lookupEvidence", () => {
	const map = parseEvidenceMarkdown(`## Successfully Exploited Vulnerabilities
### AUTH-VULN-9: x
**Proof of Impact:** done.
`);

	it("matches case-insensitively after canonicalization", () => {
		expect(lookupEvidence(map, "auth-vuln-09")?.disposition).toBe("exploited");
	});

	it("falls back to the trailing number within the per-category map", () => {
		// Queue prefix spelled differently than the evidence heading.
		expect(lookupEvidence(map, "AUTHENTICATION-VULN-9")?.disposition).toBe(
			"exploited",
		);
	});

	it("returns undefined when nothing matches", () => {
		expect(lookupEvidence(map, "AUTH-VULN-42")).toBeUndefined();
	});
});
