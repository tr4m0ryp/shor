// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import type { JoernFlow, JoernRawResult } from "../types.js";
import { parseObservations, secondOrderObservations, toTaintLanguage } from "./parse.js";

function flow(
	src: [string, number, string],
	snk: [string, number, string],
): JoernFlow {
	const s = { file: src[0], line: src[1], code: src[2], method: "m" };
	const k = { file: snk[0], line: snk[1], code: snk[2], method: "m" };
	return { source: s, sink: k, path: [s, k] };
}

/** A stored-then-used repo: bio is WRITTEN to `users` in A and RENDERED in B. */
function storedThenUsed(): JoernRawResult {
	return {
		language: "typescript",
		direct: [],
		toStore: [
			{
				store: "users",
				flows: [
					flow(
						["routes/signup.ts", 10, "req.body.bio"],
						["routes/signup.ts", 12, "db.users.insert(bio)"],
					),
				],
			},
		],
		fromStore: [
			{
				store: "users",
				vulnClass: "xss",
				cwe: "CWE-79",
				flows: [
					flow(
						["routes/profile.ts", 5, "db.users.find()"],
						["views/profile.ts", 8, "res.send(bio)"],
					),
				],
			},
		],
	};
}

describe("secondOrderObservations — DB write->read through-step", () => {
	it("bridges a write in A and a read->sink in B into one second-order flow", () => {
		const obs = parseObservations(storedThenUsed());
		expect(obs).toHaveLength(1);
		const o = obs[0]!;
		expect(o.flowKind).toBe("second_order");
		expect(o.vulnClass).toBe("xss");
		expect(o.cwe).toBe("CWE-79");
		expect(o.throughStore).toBe("users");
		// Source is where taint ENTERED (the write side); sink is the render (read side).
		expect(o.source.code).toBe("req.body.bio");
		expect(o.sink.code).toBe("res.send(bio)");
		// The stitched path crosses the synthetic persistence marker.
		expect(o.steps.some((s) => s.method === "store:users")).toBe(true);
	});

	it("tags TS/JS observations lower-confidence (weaker jssrc2cpg frontend)", () => {
		const obs = parseObservations(storedThenUsed());
		expect(obs[0]!.confidence).toBe("tentative");
		expect(obs[0]!.language).toBe("typescript");
	});

	it("requires BOTH halves: a write with no dangerous read-back yields nothing", () => {
		const raw = storedThenUsed();
		const obs = secondOrderObservations(
			{ ...raw, fromStore: [] },
			"typescript",
			"tentative",
		);
		expect(obs).toHaveLength(0);
	});

	it("requires BOTH halves: a read->sink with nothing tainted stored yields nothing", () => {
		const raw = storedThenUsed();
		const obs = secondOrderObservations(
			{ ...raw, toStore: [] },
			"typescript",
			"tentative",
		);
		expect(obs).toHaveLength(0);
	});

	it("does not join across DIFFERENT stores", () => {
		const raw = storedThenUsed();
		const shifted = {
			...raw,
			fromStore: [{ ...raw.fromStore[0]!, store: "posts" }],
		};
		const obs = secondOrderObservations(shifted, "typescript", "tentative");
		expect(obs).toHaveLength(0);
	});

	it("produces a stable, deterministic id", () => {
		const a = parseObservations(storedThenUsed());
		const b = parseObservations(storedThenUsed());
		expect(a[0]!.id).toBe(b[0]!.id);
		expect(a[0]!.id).toHaveLength(16);
	});
});

describe("parseObservations — direct flows + Java confidence", () => {
	it("emits a direct observation and marks Java firm", () => {
		const raw: JoernRawResult = {
			language: "java",
			direct: [
				{
					vulnClass: "sql_injection",
					cwe: "CWE-89",
					flows: [flow(["A.java", 3, "req.getParameter(id)"], ["A.java", 7, "st.execute(q)"])],
				},
			],
			toStore: [],
			fromStore: [],
		};
		const obs = parseObservations(raw);
		expect(obs).toHaveLength(1);
		expect(obs[0]!.flowKind).toBe("direct");
		expect(obs[0]!.vulnClass).toBe("sql_injection");
		expect(obs[0]!.confidence).toBe("firm");
	});
});

describe("toTaintLanguage", () => {
	it("passes known languages through and defaults unknown", () => {
		expect(toTaintLanguage("typescript")).toBe("typescript");
		expect(toTaintLanguage("rust")).toBe("unknown");
	});
});
