// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it, vi } from "vitest";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { clusterIdFor, clusterWithJudge, type JudgeFn } from "./manifest.js";

function mkLogger(): ActivityLogger {
	return { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

let seq = 0;
function mkFinding(over: Partial<FindingRecord> = {}): FindingRecord {
	seq += 1;
	return {
		id: `f${seq}`,
		validation_note: "",
		title: "Finding",
		category: "xss",
		cwe: "CWE-79",
		owasp_category: "A03",
		severity: "high",
		confidence: "firm",
		evidence: "",
		safe_poc: "",
		repro_steps: [],
		vulnerable_code_location: { file: "a.ts", line: 1 },
		missing_defense: "",
		remediation: "",
		status: "new",
		fingerprint: `fp-${seq}`,
		partialFingerprints: {},
		...over,
	};
}

describe("clusterWithJudge", () => {
	it("gives two findings of the same root cause (different call-sites) the same cluster_id", async () => {
		const a = mkFinding({ id: "a", fingerprint: "fp-a", vulnerable_code_location: { file: "x.ts", line: 10 } });
		const b = mkFinding({ id: "b", fingerprint: "fp-b", vulnerable_code_location: { file: "y.ts", line: 99 } });
		// b reaches the same sink as a from a different call-site → duplicate.
		const judge: JudgeFn = async (_cand, manifest) => ({
			judgment: "DUP_SKIP",
			cluster_id: manifest[0]?.cluster_id,
			reason: "same sink, different call-site",
		});

		const out = await clusterWithJudge([a, b], { judge, logger: mkLogger(), cap: 10 });

		expect(out).toHaveLength(2);
		expect(out[0]?.cluster_id).toBe(clusterIdFor(a)); // seeded from the cluster creator
		expect(out[1]?.cluster_id).toBe(out[0]?.cluster_id); // same root cause → same id
	});

	it("swaps the cluster representative on DUP_BETTER (later candidates compare against the cleaner one)", async () => {
		const a = mkFinding({ id: "a", fingerprint: "fp-a" });
		const b = mkFinding({ id: "b", fingerprint: "fp-b" });
		const c = mkFinding({ id: "c", fingerprint: "fp-c" });
		const seenReps: string[][] = [];
		const judge: JudgeFn = async (cand, manifest) => {
			seenReps.push(manifest.map((e) => e.representative.id));
			return cand.id === "b"
				? { judgment: "DUP_BETTER", cluster_id: manifest[0]?.cluster_id, reason: "cleaner example" }
				: { judgment: "DUP_SKIP", cluster_id: manifest[0]?.cluster_id, reason: "same root cause" };
		};

		const out = await clusterWithJudge([a, b, c], { judge, logger: mkLogger(), cap: 10 });

		const cid = out[0]?.cluster_id;
		expect(cid).toBeTruthy();
		expect(out.map((f) => f.cluster_id)).toEqual([cid, cid, cid]); // one stable cluster
		// `a` created the cluster (empty manifest → no judge call). Judging `b` saw `a`
		// as the representative; after the DUP_BETTER swap, judging `c` saw `b`.
		expect(seenReps).toEqual([["a"], ["b"]]);
	});

	it("fails safe to NEW when a DUP verdict's cluster_id does not resolve (no mis-merge, no drop)", async () => {
		const a = mkFinding({ id: "a", fingerprint: "fp-a" });
		const b = mkFinding({ id: "b", fingerprint: "fp-b" });
		const judge: JudgeFn = async () => ({
			judgment: "DUP_SKIP",
			cluster_id: "cl_hallucinated",
			reason: "points at a cluster that is not in the manifest",
		});

		const out = await clusterWithJudge([a, b], { judge, logger: mkLogger(), cap: 10 });

		expect(out).toHaveLength(2);
		expect(out[1]?.cluster_id).toBe(clusterIdFor(b)); // its own fresh cluster
		expect(out[1]?.cluster_id).not.toBe(out[0]?.cluster_id);
	});

	it("logs once when the manifest cap is reached and keeps capped findings as singletons", async () => {
		const logger = mkLogger();
		const findings = [
			mkFinding({ id: "a", fingerprint: "fa" }),
			mkFinding({ id: "b", fingerprint: "fb" }),
			mkFinding({ id: "c", fingerprint: "fc" }),
		];
		const judge: JudgeFn = async () => ({ judgment: "NEW", reason: "novel root cause" }); // all distinct

		const out = await clusterWithJudge(findings, { judge, logger, cap: 1 });

		expect(out).toHaveLength(3); // nothing dropped
		expect(new Set(out.map((f) => f.cluster_id)).size).toBe(3); // each its own cluster
		const capWarns = (logger.warn as ReturnType<typeof vi.fn>).mock.calls.filter((c) =>
			String(c[0]).includes("manifest cap"),
		);
		expect(capWarns).toHaveLength(1); // logged exactly once, never silent
		expect(capWarns[0]?.[1]).toMatchObject({ cap: 1 });
	});
});
