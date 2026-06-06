// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic post-check the recon validator runs after the deliverable exists.
 *
 * Two jobs, both best-effort (never throw, never block the scan):
 *
 *  1. TOOL-FLOOR AUDIT. Recon's recommendation footer tells the agent to resolve
 *     every tool as ran/skipped — but nothing VERIFIES it, so a silently-skipped
 *     tool (we saw `nuclei` never run yet the phase pass cleanly) reads as "done".
 *     We audit the live-recon FLOOR by evidence: scan the deliverable + scratchpad
 *     filenames for a trace of each floor tool and flag any with none.
 *
 *  2. API-ACCESS RECIPE GUARD. Recon is asked to persist a credential-free
 *     `api_access.json` (reachable base + how to authenticate) so downstream
 *     agents reuse the discovery instead of re-cracking it. This guard flags a
 *     run that found an API but recorded no recipe, an incomplete recipe, OR a
 *     recipe that leaked a secret (which the hygiene rule forbids).
 *
 * Findings go to `recon_coverage.json`, a flagged appendix on the deliverable,
 * and a WARN log. Evidence detection is intentionally liberal and the floor
 * intentionally small so a clean run produces no false alarms.
 */

import { fs, path } from "zx";

import type { ActivityLogger } from "../../types/activity-logger.js";
import { scratchpadDir } from "./deliverable-paths.js";

export const RECON_COVERAGE_FILENAME = "recon_coverage.json";
export const API_ACCESS_FILENAME = "api_access.json";
const APPENDIX_MARKER = "## Appendix: Recon Tool-Floor Audit";

/**
 * The live-recon FLOOR: tools whose absence is a genuine coverage gap. Each
 * entry lists the binary names that satisfy it (port discovery is satisfied by
 * EITHER naabu or nmap).
 */
const FLOOR: ReadonlyArray<{ id: string; names: string[]; why: string }> = [
	{ id: "port-scan", names: ["naabu", "nmap"], why: "port discovery" },
	{ id: "httpx", names: ["httpx"], why: "live HTTP probe / fingerprint" },
	{
		id: "nuclei",
		names: ["nuclei"],
		why: "templated misconfig/exposure sweep",
	},
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

/** Signals in the deliverable that an API/backend exists (so a recipe is owed). */
const API_SIGNAL_RE = /\/api(\/|\b)|bearer|swagger|openapi|graphql|:\d{4,5}\b/i;

/** A JWT-shaped token — the most likely secret to leak into the recipe file. */
const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+/;

export interface ReconFloorAudit {
	floor: Array<{ id: string; evidenced: boolean; why: string }>;
	/** Floor tool ids with no evidence they ran — the actionable gaps. */
	missingFloor: string[];
	recommendedRun: string[];
	recommendedMissing: string[];
}

export interface ApiAccessAudit {
	/** `api_access.json` present and parsed as an object. */
	recorded: boolean;
	apiBaseRecorded: boolean;
	authRecorded: boolean;
	/** The deliverable references an API/backend (so a recipe is expected). */
	apiSignalsInReport: boolean;
	/** A secret (e.g. JWT) appears in the recipe — a hygiene violation. */
	secretSuspected: boolean;
	/** Actionable gap ids (raised only when an API is in play). */
	gaps: string[];
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
	const haystack =
		`${deliverableText}\n${scratchpadFiles.join("\n")}`.toLowerCase();
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
 * Audit the credential-free API-access recipe. Pure: `parsed` is the parsed
 * `api_access.json` (or null when absent/unparseable), `rawText` its raw bytes
 * (for the secret scan, "" when absent), `deliverableText` the recon report
 * (for the "is there even an API?" signal). Gaps are only raised when an API is
 * actually in play, so a no-API target produces none.
 */
export function auditApiAccess(
	parsed: unknown,
	rawText: string,
	deliverableText: string,
): ApiAccessAudit {
	const apiSignalsInReport = API_SIGNAL_RE.test(deliverableText);
	const obj =
		parsed && typeof parsed === "object"
			? (parsed as Record<string, unknown>)
			: null;

	const nonEmptyString = (v: unknown): boolean =>
		typeof v === "string" && v.trim() !== "";
	const recorded = obj !== null;
	const apiBaseRecorded = !!obj && nonEmptyString(obj.apiBase);
	const authRecorded = !!obj && nonEmptyString(obj.authScheme);
	const secretSuspected = recorded && JWT_RE.test(rawText);

	const gaps: string[] = [];
	if (!recorded) {
		// Only owed when the report shows an API/backend exists.
		if (apiSignalsInReport) gaps.push("api-access-recipe");
	} else {
		if (!apiBaseRecorded) gaps.push("api-access-base");
		if (!authRecorded) gaps.push("api-access-auth");
	}
	if (secretSuspected) gaps.push("api-access-secret");

	return {
		recorded,
		apiBaseRecorded,
		authRecorded,
		apiSignalsInReport,
		secretSuspected,
		gaps,
	};
}

/** Human-readable reason per gap id. */
const GAP_REASONS: Record<string, string> = {
	"api-access-recipe":
		"the report references an API but no `api_access.json` recipe was recorded for downstream",
	"api-access-base": "`api_access.json` is missing `apiBase` (host+port+path)",
	"api-access-auth": "`api_access.json` is missing `authScheme`",
	"api-access-secret":
		"`api_access.json` appears to contain a SECRET (e.g. a JWT) — it MUST be credential-free",
};

/**
 * Human-facing appendix appended to the deliverable, or "" when both the floor
 * and the API-access recipe are clean (no noise on a clean run). Pure.
 */
export function buildReconAuditAppendix(
	floor: ReconFloorAudit,
	apiAccess: ApiAccessAudit,
): string {
	const sections: string[] = [];

	if (floor.missingFloor.length > 0) {
		const whyById = new Map(FLOOR.map((f) => [f.id, f.why]));
		const lines = floor.missingFloor
			.map(
				(id) => `- \`${id}\` — ${whyById.get(id) ?? ""} (no evidence it ran)`,
			)
			.join("\n");
		const rec =
			floor.recommendedMissing.length > 0
				? `\n\nRecommended tools with no evidence (informational): ` +
					`${floor.recommendedMissing.map((r) => `\`${r}\``).join(", ")}.`
				: "";
		sections.push(
			`### Tool-floor gaps\n\nThese live-recon FLOOR tools left no trace in this ` +
				`deliverable or the scratchpad — re-run, or justify the skip:\n\n${lines}${rec}`,
		);
	}

	if (apiAccess.gaps.length > 0) {
		const lines = apiAccess.gaps
			.map((id) => `- \`${id}\` — ${GAP_REASONS[id] ?? ""}`)
			.join("\n");
		sections.push(`### API-access recipe gaps\n\n${lines}`);
	}

	if (sections.length === 0) return "";
	return `\n\n${APPENDIX_MARKER}\n\n${sections.join("\n\n")}\n`;
}

/** Structured audit artifact. Pure. */
export function buildReconCoverage(
	floor: ReconFloorAudit,
	apiAccess: ApiAccessAudit,
): Record<string, unknown> {
	return {
		generatedBy: "recon deterministic post-validator",
		floor: floor.floor,
		missingFloor: floor.missingFloor,
		recommendedRun: floor.recommendedRun,
		recommendedMissing: floor.recommendedMissing,
		apiAccess: {
			recorded: apiAccess.recorded,
			apiBaseRecorded: apiAccess.apiBaseRecorded,
			authRecorded: apiAccess.authRecorded,
			secretSuspected: apiAccess.secretSuspected,
			gaps: apiAccess.gaps,
		},
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

/** Best-effort read of `api_access.json` → `{ parsed, rawText }`. Never throws. */
async function readApiAccess(
	sourceDir: string,
): Promise<{ parsed: unknown; rawText: string }> {
	try {
		const p = path.join(sourceDir, API_ACCESS_FILENAME);
		if (!(await fs.pathExists(p))) return { parsed: null, rawText: "" };
		const rawText = await fs.readFile(p, "utf8");
		try {
			return { parsed: JSON.parse(rawText), rawText };
		} catch {
			return { parsed: null, rawText }; // malformed — still scan raw for secrets
		}
	} catch {
		return { parsed: null, rawText: "" };
	}
}

/**
 * Run the recon tool-floor + API-access audit against an existing deliverable.
 * Best-effort: logs and swallows any error so the scan is never blocked.
 */
export async function runReconPostChecks(
	sourceDir: string,
	deliverablePath: string,
	logger: ActivityLogger,
): Promise<void> {
	try {
		const text = await fs.readFile(deliverablePath, "utf8");
		const scratch = await listScratchpad(sourceDir);
		const { parsed, rawText } = await readApiAccess(sourceDir);

		const floor = auditReconFloor(text, scratch);
		const apiAccess = auditApiAccess(parsed, rawText, text);

		await fs.writeFile(
			path.join(sourceDir, RECON_COVERAGE_FILENAME),
			`${JSON.stringify(buildReconCoverage(floor, apiAccess), null, 2)}\n`,
		);

		if (!text.includes(APPENDIX_MARKER)) {
			const appendix = buildReconAuditAppendix(floor, apiAccess);
			if (appendix) await fs.appendFile(deliverablePath, appendix);
		}

		logger.info("recon tool-floor audit", {
			floorMet: floor.floor.filter((f) => f.evidenced).length,
			floorTotal: floor.floor.length,
			recommendedRun: floor.recommendedRun.length,
			apiAccessRecorded: apiAccess.recorded,
		});
		if (floor.missingFloor.length > 0) {
			logger.warn(
				"recon floor tools with no evidence they ran (possible coverage gap)",
				{ missing: floor.missingFloor },
			);
		}
		if (apiAccess.secretSuspected) {
			logger.warn(
				"api_access.json appears to contain a secret — it MUST be credential-free (hygiene violation)",
			);
		}
		if (apiAccess.gaps.length > 0) {
			logger.warn("recon API-access recipe gaps", { gaps: apiAccess.gaps });
		}
	} catch (err) {
		logger.warn("recon post-checks failed (continuing)", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
