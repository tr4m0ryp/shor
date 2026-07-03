// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import { bm25Rank, toLexicalDoc, tokenizeCode } from "./bm25.js";

describe("tokenizeCode (code-aware)", () => {
	it("keeps code carriers and lowercases", () => {
		const t = tokenizeCode("$_GET req.body");
		expect(t).toContain("$_get");
		expect(t).toContain("req.body");
	});

	it("also emits sub-identifiers of a dotted/pathed/arrow compound", () => {
		const t = tokenizeCode("req.body.userId");
		expect(t).toContain("req.body.userid"); // whole path
		expect(t).toContain("body");
		expect(t).toContain("userid");
	});

	it("splits an arrow accessor while keeping the whole", () => {
		const t = tokenizeCode("$wpdb->query");
		expect(t).toContain("$wpdb->query");
		expect(t).toContain("$wpdb");
		expect(t).toContain("query");
	});

	it("returns empty for null/empty", () => {
		expect(tokenizeCode(null)).toEqual([]);
		expect(tokenizeCode("")).toEqual([]);
	});
});

describe("bm25Rank", () => {
	it("ranks a candidate that contains the query term above one that does not", () => {
		const docs = [
			toLexicalDoc("hit", ["CWE-89", "SQL injection", "/api/login", "db.query"]),
			// No token overlaps the query -> zero score -> dropped.
			toLexicalDoc("miss", ["open redirect", "/go", "res.redirect"]),
		];
		const ranked = bm25Rank(tokenizeCode("CWE-89 db.query"), docs);
		expect(ranked[0]).toBe("hit");
		expect(ranked).not.toContain("miss"); // zero-score docs are dropped
	});

	it("returns [] on empty docs or empty query", () => {
		expect(bm25Rank(["x"], [])).toEqual([]);
		expect(bm25Rank([], [toLexicalDoc("a", ["x"])])).toEqual([]);
	});

	it("prefers the rarer (more discriminative) term across the candidate set", () => {
		// "sqli" is rare (1 doc), "cwe-89" is common (all docs) -> the doc with the
		// rare term should outrank one that only shares the common term.
		const docs = [
			toLexicalDoc("rare", ["CWE-89", "sqli"]),
			toLexicalDoc("common1", ["CWE-89", "misc"]),
			toLexicalDoc("common2", ["CWE-89", "other"]),
		];
		const ranked = bm25Rank(tokenizeCode("CWE-89 sqli"), docs);
		expect(ranked[0]).toBe("rare");
	});
});
