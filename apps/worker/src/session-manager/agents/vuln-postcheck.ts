// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
 * Mutation-evidence backstop: the scan audit also caught agents performing
 * MUTATING actions during the read-only phase (creating MongoDB users, poisoning
 * data). `auditMutationEvidence` is a deterministic detection-after-the-fact for
 * the no-mutate prompt rail — it scans the deliverable for conservative,
 * high-signal markers a write actually landed (precision over recall: a bare
 * POST/PUT/DELETE or a plain GET read must NOT trip it).
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

/**
 * Conservative, high-signal LITERAL markers that a write actually landed during
 * the read-only phase. Each is matched as a lowercased substring → one signal.
 * Kept narrow on purpose: precision over recall.
 */
const MUTATION_MARKERS: readonly string[] = [
	"201 created",
	"created user",
	"created record",
	"account created",
	"inserted",
	"persisted",
	"poisoned",
	"deleted the",
	"updated the",
];

/**
 * An HTTP write verb co-located (same sentence, within a short window, either
 * order) with a create/mutate OUTCOME word. Catches "forged a token and POSTed
 * to create a new account" / "DELETEd the record" while a bare POST or a plain
 * GET read does NOT trip it — the outcome word is required.
 */
const WRITE_VERB = "(?:post(?:ed|s|ing)?|put|patch(?:ed)?|delete(?:d)?)";
const MUTATE_OUTCOME =
	"(?:created|inserted|persisted|new (?:user|record|account|row|document))";
const WRITE_WITH_OUTCOME_RE = new RegExp(
	`\\b${WRITE_VERB}\\b[^.]{0,80}\\b${MUTATE_OUTCOME}\\b|` +
		`\\b${MUTATE_OUTCOME}\\b[^.]{0,80}\\b${WRITE_VERB}\\b`,
);

export interface MutationEvidence {
	suspected: boolean;
	signals: string[];
}

/**
 * Scan a deliverable for evidence the agent performed a MUTATING action during
 * the read-only phase. Pure: `deliverableText` is the analysis deliverable body.
 * Each matched marker is recorded in `signals`; `suspected` is true iff any hit.
 */
export function auditMutationEvidence(
	deliverableText: string,
): MutationEvidence {
	const hay = deliverableText.toLowerCase();
	const signals: string[] = [];
	for (const marker of MUTATION_MARKERS) {
		if (hay.includes(marker)) signals.push(marker);
	}
	if (WRITE_WITH_OUTCOME_RE.test(hay)) {
		signals.push("write-verb paired with create/mutate outcome");
	}
	return { suspected: signals.length > 0, signals };
}

/** Structured audit artifact. Pure. */
export function buildVulnCoverage(
	audit: VulnFloorAudit,
	mutation: MutationEvidence = { suspected: false, signals: [] },
): Record<string, unknown> {
	return {
		generatedBy: "vuln deterministic post-validator",
		category: audit.category,
		floorTool: FLOOR_TOOL,
		floorMet: audit.floorMet,
		recommendedRun: audit.recommendedRun,
		recommendedMissing: audit.recommendedMissing,
		mutationSuspected: mutation.suspected,
		mutationSignals: mutation.signals,
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
		const mutation = auditMutationEvidence(text);

		await fs.writeFile(
			path.join(sourceDir, `${category}_vuln_coverage.json`),
			`${JSON.stringify(buildVulnCoverage(audit, mutation), null, 2)}\n`,
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
		if (mutation.suspected) {
			logger.warn(
				`vuln ${category} shows evidence of a MUTATING action in the read-only phase`,
				{ signals: mutation.signals },
			);
		}
	} catch (err) {
		logger.warn(`vuln ${category}: post-checks failed (continuing)`, {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
