// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultSpec } from "./defaults.js";
import { inferSpec, mergeSpec, specInferenceEnabled } from "./infer.js";

describe("mergeSpec — LLM overlay unions onto the deterministic default", () => {
	it("unions sources/sinks/through-steps and never drops the defaults", () => {
		const base = defaultSpec("typescript");
		const merged = mergeSpec(base, {
			sources: ["(?i)customInput"],
			sinks: [{ name: "(?i)renderTemplate", vulnClass: "ssti", cwe: "CWE-1336" }],
			sanitizers: ["(?i)cleanse"],
			throughSteps: [
				{ store: "users", writeMethods: ["saveUser"], readMethods: ["loadUser"] },
			],
		});
		expect(merged.inferredBy).toBe("llm");
		// default sources are still present…
		expect(merged.sources).toEqual(expect.arrayContaining([...base.sources]));
		// …and the LLM's are added.
		expect(merged.sources).toContain("(?i)customInput");
		expect(merged.sinks.some((s) => s.vulnClass === "ssti")).toBe(true);
		// The LLM's write/read methods merge INTO the existing "db"/"users" store.
		const users = merged.throughSteps.find((t) => t.store === "users")!;
		expect(users.writeMethods).toContain("saveUser");
		expect(users.readMethods).toContain("loadUser");
	});

	it("is idempotent — merging an empty overlay keeps the defaults", () => {
		const base = defaultSpec("java");
		const merged = mergeSpec(base, {
			sources: [],
			sinks: [],
			sanitizers: [],
			throughSteps: [],
		});
		expect(merged.sources).toEqual([...base.sources]);
		expect(merged.sinks).toHaveLength(base.sinks.length);
	});
});

describe("specInferenceEnabled", () => {
	const saved = { ...process.env };
	afterEach(() => {
		process.env = { ...saved };
	});
	it("is OFF with the opt-out flag regardless of auth", () => {
		process.env.SHOR_TAINT_LLM_SPECS = "0";
		process.env.ANTHROPIC_API_KEY = "k";
		expect(specInferenceEnabled()).toBe(false);
	});
	it("is OFF with no auth present", () => {
		delete process.env.SHOR_TAINT_LLM_SPECS;
		delete process.env.ANTHROPIC_API_KEY;
		delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
		expect(specInferenceEnabled()).toBe(false);
	});
	it("is ON with auth and no opt-out", () => {
		delete process.env.SHOR_TAINT_LLM_SPECS;
		process.env.CLAUDE_CODE_OAUTH_TOKEN = "t";
		expect(specInferenceEnabled()).toBe(true);
	});
});

describe("inferSpec — deterministic default path (LLM disabled)", () => {
	let dir = "";
	beforeEach(async () => {
		dir = await fs.mkdtemp(path.join(os.tmpdir(), "shor-taint-infer-"));
		process.env.SHOR_TAINT_LLM_SPECS = "0"; // force the no-LLM path
	});
	afterEach(async () => {
		delete process.env.SHOR_TAINT_LLM_SPECS;
		await fs.rm(dir, { recursive: true, force: true });
	});

	it("detects the language from files and returns the built-in default spec", async () => {
		await fs.writeFile(path.join(dir, "a.ts"), "export const x = 1;\n");
		await fs.writeFile(path.join(dir, "b.ts"), "export const y = 2;\n");
		const { spec, language } = await inferSpec(dir);
		expect(language).toBe("typescript");
		expect(spec.inferredBy).toBe("default");
		expect(spec.throughSteps.length).toBeGreaterThan(0);
	});

	it("skips node_modules when detecting the language", async () => {
		await fs.mkdir(path.join(dir, "node_modules", "junk"), { recursive: true });
		await fs.writeFile(path.join(dir, "node_modules", "junk", "x.py"), "y=1\n");
		await fs.writeFile(path.join(dir, "main.go"), "package main\n");
		const { language } = await inferSpec(dir);
		expect(language).toBe("go");
	});
});
