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
 * DEFAULT: ON whenever CLI/API auth is present — semantic, cross-file dedup is a
 * core part of refinement (deterministic file:line collapse cannot catch the same
 * root cause reported under different files/CWEs). Opt-OUT with `SHOR_DEDUP_JUDGE=0`.
 * With no auth (tests, unconfigured runs) it stays identity: emitted set byte-for-byte
 * unchanged, no LLM called.
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
 * ON by default, gated on CLI/API auth (mirrors `SHOR_CLI_FINALIZE`): test and
 * unconfigured runs never spawn an agent and keep today's emitted set. Opt-OUT with
 * `SHOR_DEDUP_JUDGE=0` (e.g. to skip the LLM pass on a cost/time budget).
 */
function dedupEnabled(): boolean {
	if (process.env.SHOR_DEDUP_JUDGE === "0") return false;
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
