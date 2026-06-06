// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic static-tool-floor guard for the vulnerability-analysis phase.
 *
 * The scan-00006 audit found the expected read-only static tools were run
 * inconsistently across the 7 vuln agents: `osv-scanner` never ran anywhere,
 * `httpx` was skipped by logic, `nuclei` by misconfig-web, and ssrf only reused
 * stale `semgrep` output — all silently. This mirrors the pre-recon coverage
 * census and the recon tool-floor check: per category, confirm the expected
 * static tools left a trace in THAT category's own deliverable (the per-agent
 * file is the only attributable evidence — the scratchpad is shared across the 7
 * concurrent agents), record `{category}_vuln_coverage.json`, and WARN on a gap.
 *
 * Scope note: this guard checks the STATIC read-only floor only. It deliberately
 * does NOT flag live-exploit tools run during analysis — whether the vuln phase
 * may execute live is the open static/dynamic-boundary decision (a separate
 * task); this guard is decision-independent.
 *
 * Best-effort: never throws, never blocks a scan.
 */

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";

/** The universal read-only floor every vuln agent should run. */
const FLOOR_TOOL = "semgrep";

/** Category-specific read-only tools that are expected but not the hard floor. */
const RECOMMENDED_BY_CATEGORY: Readonly<Record<string, readonly string[]>> = {
	injection: ["osv-scanner"],
	xss: [],
	auth: [],
	ssrf: [],
	authz: [],
	logic: ["httpx"],
	"misconfig-web": ["nuclei", "httpx"],
};

export interface VulnFloorAudit {
	category: string;
	/** `semgrep` (the read-only floor) left a trace in the deliverable. */
	floorMet: boolean;
	recommendedRun: string[];
	recommendedMissing: string[];
}

/**
 * Audit the static-tool floor for one category against its deliverable text.
 * Pure: `deliverableText` is the `{category}_analysis_deliverable.md` body; a
 * tool counts as evidenced if its name appears in it.
 */
export function auditVulnFloor(
	deliverableText: string,
	category: string,
): VulnFloorAudit {
	const hay = deliverableText.toLowerCase();
	const has = (t: string): boolean => hay.includes(t);
	const recommended = RECOMMENDED_BY_CATEGORY[category] ?? [];
	return {
		category,
		floorMet: has(FLOOR_TOOL),
		recommendedRun: recommended.filter(has),
		recommendedMissing: recommended.filter((t) => !has(t)),
	};
}

/** Structured audit artifact. Pure. */
export function buildVulnCoverage(audit: VulnFloorAudit): Record<string, unknown> {
	return {
		generatedBy: "vuln deterministic post-validator",
		category: audit.category,
		floorTool: FLOOR_TOOL,
		floorMet: audit.floorMet,
		recommendedRun: audit.recommendedRun,
		recommendedMissing: audit.recommendedMissing,
	};
}

/**
 * Run the static-tool-floor audit for one vuln category against its deliverable.
 * Best-effort: logs + swallows any error so validation is never blocked.
 */
export async function runVulnPostChecks(
	sourceDir: string,
	category: string,
	logger: ActivityLogger,
): Promise<void> {
	try {
		const deliverable = path.join(
			sourceDir,
			`${category}_analysis_deliverable.md`,
		);
		const text = (await fs.pathExists(deliverable))
			? await fs.readFile(deliverable, "utf8")
			: "";
		const audit = auditVulnFloor(text, category);

		await fs.writeFile(
			path.join(sourceDir, `${category}_vuln_coverage.json`),
			`${JSON.stringify(buildVulnCoverage(audit), null, 2)}\n`,
		);

		if (!audit.floorMet) {
			logger.warn(
				`vuln ${category}: no evidence the read-only floor tool '${FLOOR_TOOL}' ran (possible coverage gap)`,
			);
		}
		if (audit.recommendedMissing.length > 0) {
			logger.warn(`vuln ${category}: expected static tools with no evidence`, {
				missing: audit.recommendedMissing,
			});
		}
	} catch (err) {
		logger.warn(`vuln ${category}: post-checks failed (continuing)`, {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
