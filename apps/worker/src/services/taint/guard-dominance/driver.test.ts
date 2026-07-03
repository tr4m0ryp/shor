// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { guardDominanceEnabled, runGuardDominance } from "./driver.js";

const saved = { ...process.env };
afterEach(() => {
	process.env = { ...saved };
});

describe("guardDominanceEnabled — flag gate (default OFF)", () => {
	it("is OFF unless SHOR_GUARD_DOMINANCE=1", () => {
		expect(guardDominanceEnabled({})).toBe(false);
		expect(guardDominanceEnabled({ SHOR_GUARD_DOMINANCE: "true" })).toBe(false);
		expect(guardDominanceEnabled({ SHOR_GUARD_DOMINANCE: "1" })).toBe(true);
	});
});

describe("runGuardDominance — fail-open, never throws", () => {
	it("returns degraded:disabled when the flag is off (stock scan unchanged)", async () => {
		delete process.env.SHOR_GUARD_DOMINANCE;
		const res = await runGuardDominance("/tmp/cpg.bin");
		expect(res.findings).toHaveLength(0);
		expect(res.degraded?.reason).toBe("disabled");
	});

	it("returns degraded:no_cpg when enabled but there is no CPG to reuse", async () => {
		process.env.SHOR_GUARD_DOMINANCE = "1";
		const res = await runGuardDominance(undefined);
		expect(res.degraded?.reason).toBe("no_cpg");
	});

	it("returns degraded:query_failed when the query runner fails", async () => {
		process.env.SHOR_GUARD_DOMINANCE = "1";
		const res = await runGuardDominance("/tmp/cpg.bin", {
			runQuery: async () => false,
			semanticEnabled: false,
		});
		expect(res.degraded?.reason).toBe("query_failed");
	});

	it("parses an injected query result end-to-end without a Joern install", async () => {
		process.env.SHOR_GUARD_DOMINANCE = "1";
		const workDir = await fs.mkdtemp(path.join(os.tmpdir(), "guard-test-"));
		const res = await runGuardDominance("/tmp/cpg.bin", {
			workDir,
			semanticEnabled: false, // structural-only; no LLM in tests
			runQuery: async (_script, _cpg, outPath) => {
				await fs.writeFile(
					outPath,
					JSON.stringify({
						results: [
							{
								sink: { file: "posts.ts", line: 42, code: "db.delete(id)" },
								method: "com.app.deletePost",
								dominatingGuards: [],
								nonDominatingGuards: [],
							},
						],
					}),
					"utf8",
				);
				return true;
			},
		});
		expect(res.degraded).toBeUndefined();
		expect(res.findings).toHaveLength(1);
		expect(res.findings[0]?.disposition).toBe("missing_guard");
		expect(res.findings[0]?.structuralVerdict).toBe("unguarded");
		await fs.rm(workDir, { recursive: true, force: true });
	});
});
