// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Verbalizer guarantees under test (spec T3/R3):
 *  - every labeled field renders, in order, with a contextual metadata prefix;
 *  - the DATA FLOW arrow, ENDPOINT method+route, and code header are correct;
 *  - a near-empty finding still yields all seven labels (n/a placeholders);
 *  - the code block is late-chunked (whole under budget; windowed over budget).
 */

import { describe, expect, it } from "vitest";
import {
	DOC_LABELS,
	extractMetadata,
	lateChunkCode,
	verbalize,
} from "./index.js";

const FULL_FINDING = {
	title: "Stored XSS",
	category: "xss",
	cwe: "CWE-79",
	severity: "high",
	confidence: "confirmed",
	method: "post",
	route: "/comments",
	source: "req.body.comment",
	sink: "res.send(html)",
	description: "User comment rendered into the page without output encoding.",
	root_cause: "No HTML encoding applied to the comment field before render.",
	impact: "Session theft via injected script running in a victim's browser.",
	remediation: "HTML-encode the comment on render; add a CSP.",
	code_snippet:
		"app.post('/comments', (req, res) => { res.send(req.body.comment); });",
	vulnerable_code_location: { file: "server.js", line: 42 },
};

describe("verbalize: labeled doc", () => {
	it("renders all seven labels in order", () => {
		const v = verbalize(FULL_FINDING);
		for (const label of DOC_LABELS) {
			expect(v.doc).toContain(`${label}:`);
		}
		// Order preserved: each label index is strictly increasing in the doc.
		const positions = DOC_LABELS.map((l) => v.doc.indexOf(`${l}:`));
		const sorted = [...positions].sort((a, b) => a - b);
		expect(positions).toEqual(sorted);
	});

	it("prepends a contextual metadata prefix (CWE / class / severity / route)", () => {
		const v = verbalize(FULL_FINDING);
		expect(v.metadataPrefix).toBe(
			"[CWE=CWE-79 | class=xss | severity=high | route=POST /comments]",
		);
		expect(v.text.startsWith(v.metadataPrefix)).toBe(true);
		expect(v.text).toContain(v.doc);
	});

	it("renders the DATA FLOW arrow and the ENDPOINT method+route", () => {
		const v = verbalize(FULL_FINDING);
		expect(v.doc).toContain("DATA FLOW: req.body.comment -> res.send(html)");
		expect(v.doc).toContain("ENDPOINT: POST /comments");
		expect(v.doc).toContain(
			"VULNERABILITY: Stored XSS (CWE-79, severity=high)",
		);
	});

	it("never embeds raw JSON — the doc is prose, not the record", () => {
		const v = verbalize(FULL_FINDING);
		expect(v.text).not.toContain("{");
		expect(v.text).not.toContain('"cwe"');
	});
});

describe("verbalize: metadata + code block", () => {
	it("extracts the SQL-prefilter columns", () => {
		const meta = extractMetadata(FULL_FINDING);
		expect(meta).toMatchObject({
			cwe: "CWE-79",
			vulnClass: "xss",
			severity: "high",
			route: "POST /comments",
			source: "req.body.comment",
			sink: "res.send(html)",
			componentVer: null,
			confidence: "confirmed",
		});
	});

	it("attaches a file:line context header to the code block", () => {
		const v = verbalize(FULL_FINDING);
		expect(v.codeBlock).toContain("// server.js:42");
		expect(v.codeBlock).toContain("res.send(req.body.comment)");
	});

	it("builds component@version when both are present", () => {
		const meta = extractMetadata({ component: "lodash", version: "4.17.15" });
		expect(meta.componentVer).toBe("lodash@4.17.15");
	});
});

describe("verbalize: totality on a sparse finding", () => {
	it("renders all labels as n/a and no code vector", () => {
		const v = verbalize({});
		for (const label of DOC_LABELS) {
			expect(v.doc).toContain(`${label}: `);
		}
		expect(v.doc).toContain("DATA FLOW: n/a -> n/a");
		expect(v.codeBlock).toBeNull();
		expect(v.metadata.cwe).toBeNull();
	});
});

describe("lateChunkCode", () => {
	it("returns a whole block under the budget unchanged", () => {
		const code = "const x = 1;";
		expect(lateChunkCode(code, { maxChars: 100 })).toBe(code);
	});

	it("centers the window on the focus hint when over budget", () => {
		const body = `${"a".repeat(300)}SINK_HERE${"b".repeat(300)}`;
		const out = lateChunkCode(body, { maxChars: 100, focusHint: "SINK_HERE" });
		expect(out).toContain("SINK_HERE");
		expect(out).toContain("truncated");
		expect(out.length).toBeLessThan(body.length);
	});

	it("head-truncates when there is no focus hint", () => {
		const body = "z".repeat(500);
		const out = lateChunkCode(body, { maxChars: 100 });
		expect(out.startsWith("z".repeat(100))).toBe(true);
		expect(out).toContain("truncated");
	});
});
