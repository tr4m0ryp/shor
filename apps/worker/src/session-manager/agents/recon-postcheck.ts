// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic post-check the recon validator runs after the deliverable exists.
 *
 * Recon's recommendation footer tells the agent to resolve every tool as
 * ran/skipped — but nothing VERIFIES it, so a silently-skipped tool (we saw
 * `nuclei` never run yet the phase pass cleanly) leaves a coverage hole that
 * reads as "done". This audits the LIVE-RECON FLOOR by evidence: scan the recon
 * deliverable text and the scratchpad filenames for a trace of each floor tool,
 * record `recon_coverage.json`, append a short appendix listing any floor tool
 * with no evidence, and WARN. Best-effort — never throws, never blocks the scan.
 *
 * Evidence detection is intentionally liberal (a tool name appearing in the
 * deliverable or a scratchpad filename counts) and the floor is intentionally
 * small (port scan, HTTP probe, templated sweep) so a clean run produces no
 * false alarms; the recommended-but-not-floor tools are reported for visibility
 * only, never warned on.
 */

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import { scratchpadDir } from "./deliverable-paths.js";

export const RECON_COVERAGE_FILENAME = "recon_coverage.json";
const APPENDIX_MARKER = "## Appendix: Recon Tool-Floor Audit";

/**
 * The live-recon FLOOR: tools whose absence is a genuine coverage gap. Each
 * entry lists the binary names that satisfy it (port discovery is satisfied by
 * EITHER naabu or nmap).
 */
const FLOOR: ReadonlyArray<{ id: string; names: string[]; why: string }> = [
	{ id: "port-scan", names: ["naabu", "nmap"], why: "port discovery" },
	{ id: "httpx", names: ["httpx"], why: "live HTTP probe / fingerprint" },
	{ id: "nuclei", names: ["nuclei"], why: "templated misconfig/exposure sweep" },
];

/** Recommended but not floor — reported for visibility, never warned on. */
const RECOMMENDED = [
	"katana",
	"wafw00f",
	"arjun",
	"ffuf",
	"gau",
	"waybackurls",
	"paramspider",
	"subfinder",
	"dnsx",
];

export interface ReconFloorAudit {
	floor: Array<{ id: string; evidenced: boolean; why: string }>;
	/** Floor tool ids with no evidence they ran — the actionable gaps. */
	missingFloor: string[];
	recommendedRun: string[];
	recommendedMissing: string[];
}

/**
 * Audit the live-recon floor against textual evidence. Pure: `deliverableText`
 * is the recon report body, `scratchpadFiles` the basenames of scratchpad files.
 * A tool counts as evidenced if its name appears in either.
 */
export function auditReconFloor(
	deliverableText: string,
	scratchpadFiles: readonly string[],
): ReconFloorAudit {
	const haystack = `${deliverableText}\n${scratchpadFiles.join("\n")}`.toLowerCase();
	const has = (name: string): boolean => haystack.includes(name);

	const floor = FLOOR.map((f) => ({
		id: f.id,
		evidenced: f.names.some(has),
		why: f.why,
	}));
	const recommendedRun = RECOMMENDED.filter(has);
	return {
		floor,
		missingFloor: floor.filter((f) => !f.evidenced).map((f) => f.id),
		recommendedRun,
		recommendedMissing: RECOMMENDED.filter((r) => !has(r)),
	};
}

/**
 * Human-facing appendix appended to the deliverable, or "" when the floor is
 * fully met (no noise on a clean run). Pure.
 */
export function buildReconAuditAppendix(audit: ReconFloorAudit): string {
	if (audit.missingFloor.length === 0) return "";
	const whyById = new Map(FLOOR.map((f) => [f.id, f.why]));
	const missing = audit.missingFloor
		.map((id) => `- \`${id}\` — ${whyById.get(id) ?? ""} (no evidence it ran)`)
		.join("\n");
	const rec =
		audit.recommendedMissing.length > 0
			? `\n\nRecommended tools with no evidence (informational): ` +
				audit.recommendedMissing.map((r) => `\`${r}\``).join(", ") +
				`.`
			: "";
	return (
		`\n\n${APPENDIX_MARKER}\n\n` +
		`These live-recon FLOOR tools left no trace in this deliverable or the ` +
		`scratchpad — treat them as a coverage gap (re-run, or justify the skip):\n\n` +
		`${missing}${rec}\n`
	);
}

/** Structured audit artifact. Pure. */
export function buildReconCoverage(audit: ReconFloorAudit): Record<string, unknown> {
	return {
		generatedBy: "recon deterministic post-validator",
		floor: audit.floor,
		missingFloor: audit.missingFloor,
		recommendedRun: audit.recommendedRun,
		recommendedMissing: audit.recommendedMissing,
	};
}

/** Best-effort list of scratchpad filenames (basenames). Never throws. */
async function listScratchpad(sourceDir: string): Promise<string[]> {
	try {
		return await fs.readdir(scratchpadDir(sourceDir));
	} catch {
		return [];
	}
}

/**
 * Run the recon tool-floor audit against an existing deliverable. Best-effort:
 * logs and swallows any error so the scan is never blocked.
 */
export async function runReconPostChecks(
	sourceDir: string,
	deliverablePath: string,
	logger: ActivityLogger,
): Promise<void> {
	try {
		const text = await fs.readFile(deliverablePath, "utf8");
		const scratch = await listScratchpad(sourceDir);
		const audit = auditReconFloor(text, scratch);

		await fs.writeFile(
			path.join(sourceDir, RECON_COVERAGE_FILENAME),
			`${JSON.stringify(buildReconCoverage(audit), null, 2)}\n`,
		);

		if (!text.includes(APPENDIX_MARKER)) {
			const appendix = buildReconAuditAppendix(audit);
			if (appendix) await fs.appendFile(deliverablePath, appendix);
		}

		logger.info("recon tool-floor audit", {
			floorMet: audit.floor.filter((f) => f.evidenced).length,
			floorTotal: audit.floor.length,
			recommendedRun: audit.recommendedRun.length,
		});
		if (audit.missingFloor.length > 0) {
			logger.warn(
				"recon floor tools with no evidence they ran (possible coverage gap)",
				{ missing: audit.missingFloor },
			);
		}
	} catch (err) {
		logger.warn("recon post-checks failed (continuing)", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
