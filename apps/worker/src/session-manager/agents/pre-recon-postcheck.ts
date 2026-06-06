// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Deterministic post-checks the pre-recon validator runs after the deliverable
 * exists. Two jobs:
 *
 *  1. SECTION CONTRACT (fix #4). Downstream agents parse the deliverable by its
 *     exact numbered headings (Sections 3, 5, 7, 8, 9, 10 are a hard parse
 *     contract). A renamed/merged/dropped heading silently breaks a downstream
 *     agent hours later. We verify the required sections are present and emit a
 *     machine-readable index (`pre_recon_index.json`) so the handoff no longer
 *     depends on fuzzy heading matching — and any drift is logged *at the
 *     source*.
 *
 *  2. COVERAGE CENSUS (fix #1). Measure which backend source files the agent
 *     actually cited (see `coverage/census.ts`), write `pre_recon_coverage.json`,
 *     and append a short, clearly-marked appendix to the deliverable so the
 *     uncovered files are visible to the downstream agents that read it.
 *
 * Everything here is best-effort: the orchestrator never throws, so a scan is
 * never blocked by an audit. Pure helpers (`auditSections`, `buildPreReconIndex`,
 * `buildAuditAppendix`) are separated from the filesystem orchestration so the
 * parsing/formatting logic is unit-testable.
 */

import { fs, path } from "zx";
import type { CoverageAudit } from "../../job/coverage/census.js";
import {
	auditCoverage,
	collectBackendSourceFiles,
} from "../../job/coverage/census.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** Emitted artifacts (siblings of the deliverable). */
export const COVERAGE_AUDIT_FILENAME = "pre_recon_coverage.json";
export const INDEX_FILENAME = "pre_recon_index.json";

/** Marks the appended appendix so re-runs (resume/retry) stay idempotent. */
const APPENDIX_MARKER = "## Appendix: Deterministic Coverage Audit";

/** How many uncovered files to spell out before summarizing the remainder. */
const UNCOVERED_SAMPLE = 40;

/**
 * Sections downstream stages parse by number. `keywords` are matched
 * case-insensitively against the heading text to detect a renamed heading that
 * still carries the right number (soft "drift" vs. a hard "missing").
 */
const REQUIRED_SECTIONS: ReadonlyArray<{
	num: number;
	title: string;
	keywords: string[];
}> = [
	{
		num: 3,
		title: "Authentication & Authorization Deep Dive",
		keywords: ["auth"],
	},
	{ num: 5, title: "Attack Surface Analysis", keywords: ["attack surface"] },
	{ num: 7, title: "Injection Sources", keywords: ["injection"] },
	{
		num: 8,
		title: "Critical File Paths",
		keywords: ["critical file", "file path"],
	},
	{ num: 9, title: "XSS Sinks and Render Contexts", keywords: ["xss"] },
	{ num: 10, title: "SSRF Sinks", keywords: ["ssrf"] },
];

export interface SectionInfo {
	num: number;
	expectedTitle: string;
	present: boolean;
	/** Present with the right number but the heading text drifted from contract. */
	drifted: boolean;
	headingText?: string;
	/** Byte offset of the heading in the deliverable (lets consumers slice). */
	charOffset?: number;
}

export interface SectionAudit {
	sections: SectionInfo[];
	missing: number[];
	drifted: number[];
}

/** Numbered markdown headings, e.g. `## 7. Injection Sources`. */
const HEADING_RE = /^#{1,4}[ \t]+(\d+)\.[ \t]*(.*)$/gm;

/**
 * Check the deliverable against the downstream section-parse contract. Pure.
 * A required section is `missing` when no heading carries its number, `drifted`
 * when the number is present but none of its keywords appear in the heading.
 */
export function auditSections(text: string): SectionAudit {
	const found = new Map<number, { headingText: string; charOffset: number }>();
	for (const m of text.matchAll(HEADING_RE)) {
		if (m[1] === undefined) continue;
		const num = Number(m[1]);
		// First heading wins (a stray later "7." in prose can't override).
		if (!found.has(num)) {
			found.set(num, {
				headingText: (m[2] ?? "").trim(),
				charOffset: m.index ?? 0,
			});
		}
	}

	const sections: SectionInfo[] = REQUIRED_SECTIONS.map((req) => {
		const hit = found.get(req.num);
		if (!hit) {
			return {
				num: req.num,
				expectedTitle: req.title,
				present: false,
				drifted: false,
			};
		}
		const lower = hit.headingText.toLowerCase();
		const drifted = !req.keywords.some((k) => lower.includes(k));
		return {
			num: req.num,
			expectedTitle: req.title,
			present: true,
			drifted,
			headingText: hit.headingText,
			charOffset: hit.charOffset,
		};
	});

	return {
		sections,
		missing: sections.filter((s) => !s.present).map((s) => s.num),
		drifted: sections.filter((s) => s.drifted).map((s) => s.num),
	};
}

/** Structured, heading-independent handle on the deliverable. Pure. */
export function buildPreReconIndex(
	deliverableFilename: string,
	sectionAudit: SectionAudit,
	coverage: CoverageAudit,
): Record<string, unknown> {
	return {
		deliverable: deliverableFilename,
		generatedBy: "pre-recon deterministic post-validator",
		sections: sectionAudit.sections,
		missingSections: sectionAudit.missing,
		driftedSections: sectionAudit.drifted,
		coverage: {
			backendSourceFiles: coverage.total,
			cited: coverage.covered,
			uncovered: coverage.uncovered.length,
			ratio: Number(coverage.ratio.toFixed(3)),
		},
	};
}

/**
 * Render the human-facing appendix appended to the deliverable. Returns "" when
 * there is nothing to report (full coverage, no source to audit, contract met),
 * so a clean deliverable is left untouched. Pure.
 */
export function buildAuditAppendix(
	coverage: CoverageAudit,
	sectionAudit: SectionAudit,
): string {
	const parts: string[] = [];

	if (coverage.total > 0 && coverage.uncovered.length > 0) {
		const pct = Math.round(coverage.ratio * 100);
		const sample = coverage.uncovered.slice(0, UNCOVERED_SAMPLE);
		const more = coverage.uncovered.length - sample.length;
		parts.push(
			`### Uncovered backend source files\n\n` +
				`The deterministic census cited **${coverage.covered}/${coverage.total}** ` +
				`(${pct}%) backend source files. The following were NOT referenced ` +
				`anywhere in this report — they are unaudited source and downstream ` +
				`agents SHOULD treat them as a blind spot to re-examine:\n\n` +
				sample.map((f) => `- \`${f}\``).join("\n") +
				(more > 0
					? `\n- …and **${more}** more (see \`${COVERAGE_AUDIT_FILENAME}\`).`
					: ""),
		);
	}

	if (sectionAudit.missing.length > 0 || sectionAudit.drifted.length > 0) {
		const lines: string[] = [];
		if (sectionAudit.missing.length > 0) {
			lines.push(
				`- **Missing required sections:** ${sectionAudit.missing.join(", ")} ` +
					`(downstream agents parse these by number).`,
			);
		}
		if (sectionAudit.drifted.length > 0) {
			lines.push(
				`- **Drifted headings:** sections ${sectionAudit.drifted.join(", ")} ` +
					`are present but their titles diverge from the parse contract.`,
			);
		}
		parts.push(`### Section-contract warnings\n\n${lines.join("\n")}`);
	}

	if (parts.length === 0) return "";
	return `\n\n${APPENDIX_MARKER}\n\n${parts.join("\n\n")}\n`;
}

/**
 * Run both post-checks against a deliverable that already exists. `repoRoot` is
 * passed in (the validator already derives it) to avoid a circular import.
 * Best-effort — logs and swallows any error so the scan is never blocked.
 */
export async function runPreReconPostChecks(
	sourceDir: string,
	deliverablePath: string,
	repoRoot: string,
	logger: ActivityLogger,
): Promise<void> {
	try {
		const text = await fs.readFile(deliverablePath, "utf8");
		const sourceFiles = await collectBackendSourceFiles(repoRoot);
		const coverage = auditCoverage(sourceFiles, text);
		const sectionAudit = auditSections(text);

		await fs.writeFile(
			path.join(sourceDir, COVERAGE_AUDIT_FILENAME),
			`${JSON.stringify(coverage, null, 2)}\n`,
		);
		await fs.writeFile(
			path.join(sourceDir, INDEX_FILENAME),
			`${JSON.stringify(
				buildPreReconIndex(
					path.basename(deliverablePath),
					sectionAudit,
					coverage,
				),
				null,
				2,
			)}\n`,
		);

		// Append the audit appendix once (idempotent across resume/retry).
		if (!text.includes(APPENDIX_MARKER)) {
			const appendix = buildAuditAppendix(coverage, sectionAudit);
			if (appendix) await fs.appendFile(deliverablePath, appendix);
		}

		logger.info("pre-recon coverage census", {
			backendSourceFiles: coverage.total,
			cited: coverage.covered,
			uncovered: coverage.uncovered.length,
			ratio: Number(coverage.ratio.toFixed(2)),
		});
		if (coverage.total > 0 && coverage.ratio < 0.5) {
			logger.warn(
				"pre-recon cited under half of the backend source files — likely coverage gap",
				{ cited: coverage.covered, total: coverage.total },
			);
		}
		if (sectionAudit.missing.length > 0) {
			logger.warn(
				"pre-recon deliverable is missing required sections (downstream parse contract)",
				{ missing: sectionAudit.missing },
			);
		}
		if (sectionAudit.drifted.length > 0) {
			logger.warn(
				"pre-recon deliverable headings drifted from the parse contract",
				{
					drifted: sectionAudit.drifted,
				},
			);
		}
	} catch (err) {
		logger.warn("pre-recon post-checks failed (continuing)", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
