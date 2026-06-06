// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Screen-verdict application — the screen as PRIORITIZER, not gate (spec T14).
 *
 * STABLE seam consumed by `collectFindings` (and the measurement reconstructor)
 * BEFORE the oracle/gate. For every category it routes the N-vote panel verdicts
 * from `{category}_screen_verdicts.json` (written by `services/screen-panel`):
 * only a confident majority-`refute` rejects (`unverified_screen_rejected`,
 * terminal → manual-review appendix); `uncertain` becomes the non-terminal
 * `screen_uncertain` and `support` stays `queued`, both flowing THROUGH to
 * exploitation where the executable oracle is the real arbiter. A live PoC
 * (`exploited`) is never demoted.
 *
 * Backward compatibility: a category with no panel verdicts falls back to the
 * legacy `{category}_screen_rejected.json` audit file, preserving the pre-panel
 * behavior verbatim so nothing regresses when the panel did not run. All reads
 * are best-effort — missing/malformed files are skipped (logged), never thrown.
 */

import { FINDING_CATEGORIES } from "../../job/findings/queue.js";
import type { NormalizedVuln } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { readLegacyRejections, readScreenVerdicts } from "./reader.js";
import { applyLegacyRejections, applyVerdictEntries } from "./router.js";

/**
 * Apply screen routing to the normalized queue, in place. Returns the same array
 * (extended with any synthesized terminal entries) for call-site chaining.
 */
export function applyScreenVerdicts(
	vulns: NormalizedVuln[],
	deliverablesPath: string,
	logger: ActivityLogger,
): NormalizedVuln[] {
	for (const category of FINDING_CATEGORIES) {
		const verdicts = readScreenVerdicts(deliverablesPath, category, logger);
		if (verdicts !== undefined) {
			// The panel ran for this category → fail-open routing wins. (An absent
			// OR malformed verdicts file reads as `undefined`, so a corrupt panel
			// write safely falls back to the legacy file below instead of silently
			// discarding its refutations.)
			applyVerdictEntries(vulns, category, verdicts);
			continue;
		}
		// BACKWARD-COMPAT: no usable panel verdicts → preserve the legacy behavior
		// when the pre-panel `{category}_screen_rejected.json` audit file is present.
		const legacy = readLegacyRejections(deliverablesPath, category, logger);
		if (legacy !== undefined) applyLegacyRejections(vulns, category, legacy);
	}
	return vulns;
}
