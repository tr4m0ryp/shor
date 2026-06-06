// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Finding de-duplication / clustering — STABLE seam (Task 014, spec T12).
 *
 * Clusters findings by ROOT CAUSE (shared sink / sanitizer-gap / root function),
 * NOT by call-site, using a serial accepted-manifest LLM judge (see `judge.ts` /
 * `manifest.ts`). Each finding is returned stamped with a stable `cluster_id`
 * (same root cause → same id); nothing is dropped. `fingerprint` is left untouched
 * — `cluster_id` is purely additive grouping identity.
 *
 * DEFAULT: identity. The judge is opt-in (`SHOR_DEDUP_JUDGE=1` + CLI/API auth);
 * when disabled the emitted set is byte-for-byte unchanged and no LLM is called,
 * so the seam stays a no-op for every caller that has not enabled it.
 */

import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { judgeFinding } from "./judge.js";
import { clusterWithJudge, type JudgeFn } from "./manifest.js";

/** Options threaded to the dedup judge (deliverables location + logger). */
export interface ClusterOptions {
	deliverablesPath: string;
	logger: ActivityLogger;
}

/**
 * Manifest size cap: the most representatives shown to the judge in one prompt.
 * Beyond this, additional clusters stay singletons (logged, never silent).
 */
export const DEFAULT_MANIFEST_CAP = 60;

/**
 * The judge is opt-in and requires CLI/API auth (mirrors `SHOR_CLI_FINALIZE`), so
 * test and unconfigured runs never spawn an agent and keep today's emitted set.
 */
function dedupEnabled(): boolean {
	if (process.env.SHOR_DEDUP_JUDGE !== "1") return false;
	return !!(process.env.CLAUDE_CODE_OAUTH_TOKEN || process.env.ANTHROPIC_API_KEY);
}

/**
 * Cluster findings by root cause. Async because the judge runs an LLM per finding
 * (`runStructured`). DEFAULT: identity — returns `findings` unchanged when the
 * judge is disabled or there is nothing to cluster.
 */
export async function clusterFindings(
	findings: FindingRecord[],
	opts: ClusterOptions,
): Promise<FindingRecord[]> {
	if (findings.length === 0 || !dedupEnabled()) return findings;

	const judge: JudgeFn = (candidate, manifest) =>
		judgeFinding(candidate, manifest, {
			deliverablesPath: opts.deliverablesPath,
			logger: opts.logger,
		});

	return clusterWithJudge(findings, {
		judge,
		logger: opts.logger,
		cap: DEFAULT_MANIFEST_CAP,
	});
}
