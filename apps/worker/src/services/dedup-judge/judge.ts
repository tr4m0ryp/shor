// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * The LLM dedup judge call.
 *
 * Runs ONE structured-output agent per candidate (schema-validated `Judgment`) and
 * FAILS OPEN to NEW: any agent failure, missing structured output, or unexpected
 * error collapses to `{ judgment: "NEW", … }` via `parseOr`, so a flaky judge can
 * never silently drop a finding (the worst case is a missed merge, not a loss).
 */

import {
	type Judgment,
	judgmentSchema,
	parseOr,
	runStructured,
} from "../../ai/structured/index.js";
import type { FindingRecord } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { ManifestEntry } from "./manifest.js";
import { buildJudgePrompt } from "./prompt.js";

/** Plumbing the judge needs: where the agent runs + a logger. */
export interface JudgeContext {
	deliverablesPath: string;
	logger: ActivityLogger;
}

/** Fail-open verdict: treat the candidate as a new cluster so nothing is dropped. */
const FAIL_OPEN_NEW: Judgment = {
	judgment: "NEW",
	reason: "fail-open: dedup judge unavailable or returned no structured output",
};

/**
 * Judge one candidate against the manifest. Never throws; returns the parsed
 * `Judgment` on success or {@link FAIL_OPEN_NEW} on any failure.
 */
export async function judgeFinding(
	candidate: FindingRecord,
	manifest: ManifestEntry[],
	ctx: JudgeContext,
): Promise<Judgment> {
	const result = await runStructured<Judgment>({
		prompt: buildJudgePrompt(candidate, manifest),
		sourceDir: ctx.deliverablesPath,
		schema: judgmentSchema,
		agentName: "dedup-judge",
		logger: ctx.logger,
	});
	return parseOr(result, FAIL_OPEN_NEW);
}
