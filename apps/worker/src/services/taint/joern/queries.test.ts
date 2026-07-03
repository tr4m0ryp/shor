// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import type { TaintSpec } from "../types.js";
import { buildTaintScript, groupSinks, joernLanguageFlag } from "./queries.js";

const spec: TaintSpec = {
	language: "typescript",
	sources: ["(?i)get(Query|Body).*"],
	sinks: [
		{ name: "(?i).*execute.*", vulnClass: "sql_injection", cwe: "CWE-89" },
		{ name: "(?i).*rawQuery.*", vulnClass: "sql_injection", cwe: "CWE-89" },
		{ name: "(?i).*send.*", vulnClass: "xss", cwe: "CWE-79" },
	],
	sanitizers: ["(?i).*escape.*"],
	throughSteps: [
		{ store: "users", writeMethods: ["(?i)insert"], readMethods: ["(?i)find"] },
	],
	inferredBy: "llm",
};

describe("groupSinks", () => {
	it("groups sink matchers by vuln class and keeps the first CWE", () => {
		const groups = groupSinks(spec.sinks);
		expect(groups).toHaveLength(2);
		const sqli = groups.find((g) => g.vulnClass === "sql_injection")!;
		expect(sqli.patterns).toHaveLength(2);
		expect(sqli.cwe).toBe("CWE-89");
	});
});

describe("joernLanguageFlag", () => {
	it("maps JS and TS to the single JSSRC frontend", () => {
		expect(joernLanguageFlag("javascript")).toBe("JSSRC");
		expect(joernLanguageFlag("typescript")).toBe("JSSRC");
	});
	it("maps java to JAVASRC and returns undefined for unknown", () => {
		expect(joernLanguageFlag("java")).toBe("JAVASRC");
		expect(joernLanguageFlag("unknown")).toBeUndefined();
	});
});

describe("buildTaintScript", () => {
	const script = buildTaintScript(spec);

	it("is a Joern @main script that imports the CPG and writes the out-file", () => {
		expect(script).toContain("@main def exec(cpgFile: String, outFile: String)");
		expect(script).toContain("importCpg(cpgFile)");
		expect(script).toContain("os.write.over(os.Path(outFile)");
	});

	it("emits all three query families (direct, toStore, fromStore)", () => {
		expect(script).toContain("val direct = ujson.Arr()");
		expect(script).toContain("val toStore = ujson.Arr()");
		expect(script).toContain("val fromStore = ujson.Arr()");
		expect(script).toContain("reachableByFlows");
	});

	it("wires the through-step store into BOTH halves", () => {
		// write side (source -> store) and read side (store -> sink) both name the store.
		const storeHits = script.split('"users"').length - 1;
		expect(storeHits).toBeGreaterThanOrEqual(2);
	});

	it("embeds the source/sink/sanitizer matchers and the CWE tags", () => {
		expect(script).toContain("get(Query|Body)");
		expect(script).toContain("execute");
		expect(script).toContain("escape");
		expect(script).toContain("CWE-89");
	});

	it("applies the sanitizer filter to dropped paths", () => {
		expect(script).toContain("filterNot(");
		expect(script).toContain("sanitizers.exists");
	});

	it("matches sources by NAME or CODE (the validated JS/TS frontend fix)", () => {
		expect(script).toContain("cpg.call.name(pats: _*) ++ cpg.call.code(pats: _*)");
	});
});
