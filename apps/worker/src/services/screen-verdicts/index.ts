// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Screen-verdict application (T4 adversarial-screen → emission gate).
 *
 * The adversarial screen agents write `{category}_screen_rejected.json` audit
 * files for the hypotheses they refuted before exploitation. This module reads
 * those files and stamps the matching queue entries `unverified_screen_rejected`
 * (synthesizing an entry when the raw queue no longer carries the id) so the
 * findings gate routes them to the manual-review appendix and OUT of the emitted
 * set — exactly like `unverified_out_of_scope`. A live PoC still wins: an
 * `exploited` finding is never demoted.
 *
 * This is the STABLE seam consumed by `collectFindings`. The default below
 * preserves today's behavior verbatim (the logic previously inlined in
 * `job/findings/index.ts`); task 012 replaces it with the screen-panel verdict
 * model without touching the call-site.
 */

import fs from "node:fs";
import path from "node:path";
import { FINDING_CATEGORIES } from "../../job/findings/queue.js";
import type { FindingCategory, NormalizedVuln } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

const SCREEN_REJECTED_SUFFIX = "_screen_rejected.json";

/**
 * Read every `{category}_screen_rejected.json` audit file (written by the
 * adversarial screen agents) into a `category → (id → reason)` map. Each file is a
 * JSON array of `{ id, screen_reason }`. Best-effort: a missing or malformed file
 * is skipped (a screen that refuted nothing simply writes no rejections).
 */
function readScreenRejections(
	deliverablesPath: string,
	logger: ActivityLogger,
): Map<FindingCategory, Map<string, string>> {
	const out = new Map<FindingCategory, Map<string, string>>();
	for (const category of FINDING_CATEGORIES) {
		const file = path.join(
			deliverablesPath,
			`${category}${SCREEN_REJECTED_SUFFIX}`,
		);
		try {
			if (!fs.existsSync(file)) continue;
			const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
			if (!Array.isArray(parsed)) continue;
			const byId = new Map<string, string>();
			for (const entry of parsed) {
				if (!entry || typeof entry !== "object") continue;
				const rec = entry as Record<string, unknown>;
				const id = typeof rec.id === "string" ? rec.id.trim() : "";
				if (!id) continue;
				byId.set(
					id,
					typeof rec.screen_reason === "string" ? rec.screen_reason : "",
				);
			}
			if (byId.size > 0) out.set(category, byId);
		} catch (err) {
			logger.warn("Failed to read/parse screen-rejected file; skipping", {
				file,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return out;
}

/**
 * Apply the adversarial screen verdicts to the normalized queue, in place.
 *
 * Marks each refuted hypothesis `unverified_screen_rejected` (or synthesizes an
 * entry when the raw queue no longer carries it), except where a live PoC already
 * proved it (`exploited` is never demoted). Returns the same array (extended with
 * any synthesized entries) for call-site chaining.
 */
export function applyScreenVerdicts(
	vulns: NormalizedVuln[],
	deliverablesPath: string,
	logger: ActivityLogger,
): NormalizedVuln[] {
	const rejections = readScreenRejections(deliverablesPath, logger);
	for (const [category, byId] of rejections) {
		for (const [id, reason] of byId) {
			const match = vulns.find((v) => v.category === category && v.id === id);
			if (match) {
				if (match.disposition !== "exploited") {
					match.disposition = "unverified_screen_rejected";
					if (reason.trim()) match.evidenceText = reason;
				}
			} else {
				vulns.push({
					category,
					id,
					raw: { ID: id },
					disposition: "unverified_screen_rejected",
					evidenceText: reason,
				});
			}
		}
	}
	return vulns;
}
