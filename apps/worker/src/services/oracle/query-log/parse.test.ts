// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Pure-logic tests for the query-log parser + classifier: Postgres log parsing,
 * inline-vs-bound classification, and marker minting.
 */

import { describe, expect, it } from "vitest";
import { classifyRecords, mintMarker, parsePostgresRecords, parseRecords } from "./index.js";

const TOK = "shor-11111111-2222-3333-4444-555555555555";
const PREFIX = "2026-07-03 12:00:00.000 UTC [123]";

/** Simple protocol: a vulnerable, string-concatenated query — marker lands inline. */
const INLINE_LOG = `${PREFIX} LOG:  statement: SELECT * FROM users WHERE name = 'x' OR '1'='1' /* ${TOK} */`;

/** Extended protocol: a parameterized query — marker only in the bound value. */
const PARAM_LOG = [
	`${PREFIX} LOG:  execute <unnamed>: SELECT * FROM users WHERE name = $1`,
	`${PREFIX} DETAIL:  parameters: $1 = 'x'' OR ''1''=''1 /* ${TOK} */'`,
].join("\n");

/** A syntactically broken injection: the original SQL is echoed under STATEMENT:. */
const ERROR_STATEMENT_LOG = [
	`${PREFIX} ERROR:  unterminated quoted string at or near "'/* ${TOK} */"`,
	`${PREFIX} STATEMENT:  SELECT * FROM users WHERE name = ''' /* ${TOK} */`,
].join("\n");

/** A multi-line statement: continuation lines carry no severity tag. */
const MULTILINE_LOG = [`${PREFIX} LOG:  statement: SELECT *`, "\tFROM users", `\tWHERE id = 1 /* ${TOK} */`].join(
	"\n",
);

describe("parsePostgresRecords", () => {
	it("classifies simple-protocol statement text as a statement record", () => {
		const recs = parsePostgresRecords(INLINE_LOG);
		expect(recs).toHaveLength(1);
		expect(recs[0]?.kind).toBe("statement");
		expect(recs[0]?.text).toContain(TOK);
	});

	it("splits execute SQL (statement) from its bound parameters (parameter)", () => {
		const recs = parsePostgresRecords(PARAM_LOG);
		expect(recs).toHaveLength(2);
		expect(recs[0]?.kind).toBe("statement");
		expect(recs[0]?.text).not.toContain(TOK); // placeholder $1, marker not inline
		expect(recs[1]?.kind).toBe("parameter");
		expect(recs[1]?.text).toContain(TOK);
	});

	it("treats the STATEMENT: echo of an errored query as statement text", () => {
		const recs = parsePostgresRecords(ERROR_STATEMENT_LOG);
		expect(recs.find((r) => r.kind === "statement")?.text).toContain(TOK);
		expect(recs.find((r) => r.kind === "other")?.text).toContain(TOK); // ERROR: echo
	});

	it("folds continuation lines into the open multi-line statement", () => {
		const recs = parsePostgresRecords(MULTILINE_LOG);
		expect(recs).toHaveLength(1);
		expect(recs[0]?.kind).toBe("statement");
		expect(recs[0]?.text).toContain("FROM users");
		expect(recs[0]?.text).toContain(TOK);
	});

	it("returns [] for unimplemented dialects (seam, not a false clean)", () => {
		expect(parseRecords(INLINE_LOG, "mysql")).toEqual([]);
		expect(parseRecords(INLINE_LOG, "mariadb")).toEqual([]);
	});
});

describe("classifyRecords (inline vs bound)", () => {
	it("marker inline in statement text => injected", () => {
		const res = classifyRecords(parsePostgresRecords(INLINE_LOG), TOK);
		expect(res.verdict).toBe("injected");
		expect(res.inlineCount).toBe(1);
	});

	it("marker only as a bound parameter => parameterized (FP-demotion)", () => {
		const res = classifyRecords(parsePostgresRecords(PARAM_LOG), TOK);
		expect(res).toMatchObject({ verdict: "parameterized", inlineCount: 0, paramCount: 1 });
	});

	it("errored injection still classifies injected via the STATEMENT: echo", () => {
		expect(classifyRecords(parsePostgresRecords(ERROR_STATEMENT_LOG), TOK).verdict).toBe("injected");
	});

	it("inline presence dominates a coexisting bound copy", () => {
		const res = classifyRecords(parsePostgresRecords(`${INLINE_LOG}\n${PARAM_LOG}`), TOK);
		expect(res).toMatchObject({ verdict: "injected", inlineCount: 1, paramCount: 1 });
	});

	it("absent marker => not_found", () => {
		expect(classifyRecords(parsePostgresRecords(INLINE_LOG), "shor-absent").verdict).toBe("not_found");
	});
});

describe("mintMarker", () => {
	it("wraps a unique shor-<uuid> token in a SQL comment", () => {
		const a = mintMarker();
		const b = mintMarker();
		expect(a.token).toMatch(/^shor-[0-9a-f-]{36}$/);
		expect(a.marker).toBe(`/* ${a.token} */`);
		expect(a.token).not.toBe(b.token);
	});
});
