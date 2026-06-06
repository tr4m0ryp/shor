// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Recursive `@include(...)` resolver (task 001 / spec T3). Covers: top-level
 * expansion stays byte-identical to the old single-pass code; nested includes
 * (A -> B -> C) expand to a fixpoint; includes resolve root-relative at every
 * depth; cycles (direct + self) reject without hanging; the path-traversal guard
 * fires at the top AND nested levels; the depth cap bounds deep acyclic chains;
 * and a real prompt's nested include self-heals.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { PROMPTS_DIR } from "../../paths.js";
import { PentestError } from "../error-handling.js";
import { processIncludes } from "./includes.js";

let baseDir = "";

/** Write `content` to `rel` under the temp base dir, creating parent dirs. */
async function write(rel: string, content: string): Promise<void> {
	const full = join(baseDir, rel);
	await mkdir(join(full, ".."), { recursive: true });
	await writeFile(full, content, "utf8");
}

beforeEach(async () => {
	baseDir = await mkdtemp(join(tmpdir(), "shor-includes-"));
});

afterEach(async () => {
	await rm(baseDir, { recursive: true, force: true });
});

describe("processIncludes — top-level (unchanged behavior)", () => {
	it("inlines a single include byte-for-byte", async () => {
		await write("child.txt", "CHILD-CONTENT");
		const out = await processIncludes("before @include(child.txt) after", baseDir);
		// Exactly what the prior single-pass code produced — no drift.
		expect(out).toBe("before CHILD-CONTENT after");
	});

	it("inlines multiple includes in source order", async () => {
		await write("a.txt", "AAA");
		await write("b.txt", "BBB");
		const out = await processIncludes("x @include(a.txt) y @include(b.txt) z", baseDir);
		expect(out).toBe("x AAA y BBB z");
	});
});

describe("processIncludes — recursive expansion", () => {
	it("expands a nested chain A -> B -> C to a fixpoint", async () => {
		await write("a.txt", "A[@include(b.txt)]");
		await write("b.txt", "B[@include(c.txt)]");
		await write("c.txt", "C");
		const out = await processIncludes("@include(a.txt)", baseDir);
		expect(out).toBe("A[B[C]]");
		// Fixpoint reached: not a single directive survives.
		expect(out).not.toContain("@include(");
	});

	it("resolves nested includes root-relative (base dir is constant)", async () => {
		// b.txt lives in a subdir but references c.txt root-relative, exactly how
		// the real prompts author nested includes (e.g. shared/_exploit-scope.txt).
		await write("a.txt", "@include(sub/b.txt)");
		await write("sub/b.txt", "B<@include(c.txt)>");
		await write("c.txt", "C-ROOT");
		const out = await processIncludes("@include(a.txt)", baseDir);
		expect(out).toBe("B<C-ROOT>");
	});

	it("treats a diamond (A->B,A->C, B->D,C->D) as non-cyclic", async () => {
		await write("a.txt", "@include(b.txt)+@include(c.txt)");
		await write("b.txt", "B@include(d.txt)");
		await write("c.txt", "C@include(d.txt)");
		await write("d.txt", "D");
		const out = await processIncludes("@include(a.txt)", baseDir);
		expect(out).toBe("BD+CD");
	});
});

describe("processIncludes — cycle detection", () => {
	it("rejects a direct cycle A -> B -> A without hanging", { timeout: 1000 }, async () => {
		await write("a.txt", "@include(b.txt)");
		await write("b.txt", "@include(a.txt)");
		await expect(processIncludes("@include(a.txt)", baseDir)).rejects.toThrow(
			/Cyclic @include/,
		);
	});

	it("rejects a self-include cycle", { timeout: 1000 }, async () => {
		await write("self.txt", "loop @include(self.txt)");
		await expect(processIncludes("@include(self.txt)", baseDir)).rejects.toThrow(
			PentestError,
		);
	});
});

describe("processIncludes — path-traversal guard", () => {
	it("blocks a traversal escape at the top level", async () => {
		await expect(processIncludes("@include(../escape.txt)", baseDir)).rejects.toThrow(
			/Path traversal/,
		);
	});

	it("blocks a traversal escape nested inside an included file", async () => {
		await write("a.txt", "@include(b.txt)");
		await write("b.txt", "@include(../../escape.txt)");
		await expect(processIncludes("@include(a.txt)", baseDir)).rejects.toThrow(
			/Path traversal/,
		);
	});
});

describe("processIncludes — depth cap", () => {
	it("rejects a deep acyclic chain past the cap without hanging", { timeout: 2000 }, async () => {
		// 0..10 each include the next; distinct paths, so the stack-based cycle
		// guard never fires — only the depth cap stops the descent.
		for (let i = 0; i <= 10; i++) {
			await write(`f${i}.txt`, i < 10 ? `@include(f${i + 1}.txt)` : "LEAF");
		}
		await expect(processIncludes("@include(f0.txt)", baseDir)).rejects.toThrow(
			/depth cap/,
		);
	});
});

describe("processIncludes — real prompt self-heals", () => {
	it("expands the nested @include(shared/_authorization.txt) in _exploit-scope.txt", async () => {
		const raw = await readFile(
			join(PROMPTS_DIR, "shared", "_exploit-scope.txt"),
			"utf8",
		);
		// Sanity: the fixture really does carry the nested directive.
		expect(raw).toContain("@include(shared/_authorization.txt)");
		const out = await processIncludes(raw, PROMPTS_DIR);
		// The previously-dropped authorization framing is now present...
		expect(out).toContain("AUTHORIZED SECURITY ASSESSMENT");
		// ...and no directive is left unexpanded.
		expect(out).not.toContain("@include(");
	});
});
