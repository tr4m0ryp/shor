// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from "vitest";
import {
	confidenceForLanguage,
	defaultSpec,
	detectLanguageFromFiles,
	languageForPath,
} from "./defaults.js";

describe("languageForPath", () => {
	it("maps known extensions and ignores others", () => {
		expect(languageForPath("src/a.ts")).toBe("typescript");
		expect(languageForPath("src/a.js")).toBe("javascript");
		expect(languageForPath("Main.java")).toBe("java");
		expect(languageForPath("README.md")).toBeUndefined();
	});
});

describe("detectLanguageFromFiles", () => {
	it("picks the dominant language by count", () => {
		expect(detectLanguageFromFiles(["a.py", "b.py", "c.js"])).toBe("python");
	});
	it("breaks a JS/TS tie in favour of TS (transpiled-output tie-break)", () => {
		expect(detectLanguageFromFiles(["a.ts", "b.js"])).toBe("typescript");
	});
	it("returns unknown for no known source files", () => {
		expect(detectLanguageFromFiles(["README.md", "LICENSE"])).toBe("unknown");
	});
});

describe("confidenceForLanguage", () => {
	it("marks JS/TS tentative and everything else firm", () => {
		expect(confidenceForLanguage("javascript")).toBe("tentative");
		expect(confidenceForLanguage("typescript")).toBe("tentative");
		expect(confidenceForLanguage("java")).toBe("firm");
		expect(confidenceForLanguage("python")).toBe("firm");
	});
});

describe("defaultSpec", () => {
	it("always ships a DB write->read through-step (second-order backbone)", () => {
		const spec = defaultSpec("typescript");
		expect(spec.inferredBy).toBe("default");
		expect(spec.throughSteps.length).toBeGreaterThan(0);
		expect(spec.throughSteps[0]!.writeMethods.length).toBeGreaterThan(0);
		expect(spec.throughSteps[0]!.readMethods.length).toBeGreaterThan(0);
		expect(spec.sinks.some((s) => s.vulnClass === "sql_injection")).toBe(true);
	});
});
