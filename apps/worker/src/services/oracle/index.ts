// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Oracle phase (post-exploitation adjudication) — STABLE seam.
 *
 * Two entry points, both no-op by default so today's behavior is unchanged:
 *   - `runOraclePhase(ctx)` runs as a pipeline phase AFTER exploitation, with the
 *     full per-scan `AgentContext`. Task 013 fills it (e.g. an adjudicator agent
 *     that reconciles exploited / screened / blocked dispositions on disk).
 *   - `applyOracleDispositions(vulns, …)` runs inside `collectFindings`, between
 *     the screen verdicts and the emission gate, to overlay any oracle
 *     adjudication onto the normalized queue. Identity by default.
 *
 * The `AgentContext` type is imported type-only from the pipeline, so there is no
 * runtime dependency back into `job/pipeline` (the import is erased) and no
 * import cycle.
 */

import type { AgentContext } from "../../job/pipeline.js";
import type { NormalizedVuln } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/**
 * Run the post-exploitation oracle phase. DEFAULT: no-op (behavior unchanged).
 * Task 013 fills this with the adjudication pass.
 */
export async function runOraclePhase(ctx: AgentContext): Promise<void> {
	// No-op skeleton. `ctx` carries deliverablesPath, container, params, progress
	// and logger — everything task 013 needs to drive the adjudication.
	void ctx;
}

/**
 * Overlay oracle adjudication onto the normalized queue. DEFAULT: identity —
 * returns `vulns` unchanged. Task 013 fills this.
 */
export function applyOracleDispositions(
	vulns: NormalizedVuln[],
	deliverablesPath: string,
	logger: ActivityLogger,
): NormalizedVuln[] {
	void deliverablesPath;
	void logger;
	return vulns;
}
