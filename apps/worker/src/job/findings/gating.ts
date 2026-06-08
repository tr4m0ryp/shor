// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Coverage gating for finding collection (T3).
 *
 * A finding whose enforcing tier was NOT in the analyzed source AND that was not
 * live-exploited cannot be verified from this scan. It is marked
 * `unverified_out_of_scope`, EXCLUDED from the emitted set, and written to a
 * separate manual-review appendix deliverable. Exploited findings are NEVER
 * gated (a live PoC overrides missing source). When no manifest exists, no
 * gating is applied — a full-stack scan that produced no manifest must not
 * regress.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import {
	COVERAGE_MANIFEST_FILENAME,
	isTierCovered,
	normalizeManifest,
} from "../coverage/index.js";
import type { CoverageManifest, CoverageTier } from "../coverage/index.js";
import { applyCoherenceGate } from "./coherence.js";
import { readLaneStatus } from "./lane-status.js";
import { toFindingRecords } from "./mapping.js";
import { tagScope } from "./scope-tagger.js";
import type {
	FindingCategory,
	FindingRecord,
	NormalizedVuln,
	VulnDisposition,
} from "./types.js";

export const MANUAL_REVIEW_APPENDIX_FILE = "manual_review_appendix.json";

/**
 * Dispositions that are EXCLUDED from the emitted set and routed to the
 * manual-review appendix: T3 coverage / failed-lane (`unverified_out_of_scope`)
 * and T4 adversarial-screen rejection (`unverified_screen_rejected`). Both are
 * terminal — a later gate must never overwrite one with the other (the appendix
 * keeps WHY each finding was set aside).
 */
function isGatedOut(disposition: VulnDisposition | undefined): boolean {
	return (
		disposition === "unverified_out_of_scope" ||
		disposition === "unverified_screen_rejected" ||
		// T2/T3: scaffolding-target exploits, privileged-only "escalations", and
		// review-refuted findings are terminal too — set aside to the appendix, not deleted.
		disposition === "out_of_scope_target" ||
		disposition === "exploited_privileged" ||
		disposition === "refuted_on_review"
	);
}

/**
 * Architectural tier whose source would implement/enforce each finding class's
 * control. Server-side classes (authz/auth/injection/ssrf) are enforced in the
 * BACKEND. XSS output-encoding is attributed to the FRONTEND when frontend
 * source exists to carry it, else it falls to the backend (server-rendered
 * templating) — see {@link enforcingTier}.
 */
const CATEGORY_ENFORCING_TIER: Record<FindingCategory, CoverageTier> = {
	injection: "backend",
	ssrf: "backend",
	auth: "backend",
	authz: "backend",
	xss: "frontend",
	// Business-logic invariants (workflow/state, mass assignment, race, GraphQL
	// authz) and web-security misconfiguration (CORS/CSP, redirects, smuggling,
	// JWT verification) are both enforced server-side.
	logic: "backend",
	"misconfig-web": "backend",
};

/** Tier whose coverage decides whether `category` is in/out of analyzed scope. */
function enforcingTier(
	category: FindingCategory,
	manifest: CoverageManifest,
): CoverageTier {
	const tier = CATEGORY_ENFORCING_TIER[category];
	// XSS only counts as a frontend concern when there is frontend source to
	// carry the encoding control; otherwise the responsibility is server-side.
	if (tier === "frontend" && !isTierCovered(manifest, "frontend")) return "backend";
	return tier;
}

/**
 * Read + normalize `coverage_manifest.json` from `deliverablesPath`, or
 * `undefined` when it is absent/unparseable. Read SYNCHRONOUSLY on purpose: the
 * coverage module's async `readManifest` cannot be used without making
 * `collectFindings` async, which would break its synchronous callers
 * (cli-finalization.ts). Absence MUST disable gating entirely.
 */
function readCoverageManifest(
	deliverablesPath: string,
	logger: ActivityLogger,
): CoverageManifest | undefined {
	const file = path.join(deliverablesPath, COVERAGE_MANIFEST_FILENAME);
	try {
		if (!fs.existsSync(file)) return undefined;
		return normalizeManifest(JSON.parse(fs.readFileSync(file, "utf8")));
	} catch (err) {
		logger.warn("Failed to read/parse coverage manifest; gating disabled", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
		return undefined;
	}
}

/**
 * Persist the gated-out findings (`unverified_out_of_scope` or
 * `unverified_screen_rejected`) to a separate deliverable so a reviewer can see
 * what was set aside. Best-effort: a write failure never blocks emission. No file
 * is written when nothing was gated out, keeping the no-manifest / full-coverage
 * path identical to before.
 */
function writeManualReviewAppendix(
	deliverablesPath: string,
	appendix: FindingRecord[],
	logger: ActivityLogger,
): void {
	if (appendix.length === 0) return;
	const file = path.join(deliverablesPath, MANUAL_REVIEW_APPENDIX_FILE);
	try {
		const doc = {
			note:
				"Findings set aside from the emitted attack surface and preserved for " +
				"manual review. Each carries its own disposition: " +
				"`unverified_out_of_scope` (enforcing tier not in the analyzed source, " +
				"or the category's validation lane failed, and not live-confirmed) or " +
				"`unverified_screen_rejected` (the adversarial screen refuted the " +
				"hypothesis before exploitation). Excluded from the emitted attack " +
				"surface; review manually.",
			findings: appendix,
		};
		fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
		logger.info("Wrote manual-review appendix (gated-out unconfirmed findings)", {
			file,
			count: appendix.length,
		});
	} catch (err) {
		logger.warn("Failed to write manual-review appendix; continuing", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

/**
 * Read back the manual-review appendix (the gated-out findings:
 * `unverified_out_of_scope` and `unverified_screen_rejected`) so the dashboard can
 * surface them under a dedicated "manual review" filter. Tolerates absence /
 * malformed JSON → returns []. These findings are NEVER part of the emitted or
 * attack-surface set; the dashboard segregates them purely by their disposition.
 */
export function readManualReviewAppendix(
	deliverablesPath: string,
	logger: ActivityLogger,
): FindingRecord[] {
	const file = path.join(deliverablesPath, MANUAL_REVIEW_APPENDIX_FILE);
	try {
		if (!fs.existsSync(file)) return [];
		const doc = JSON.parse(fs.readFileSync(file, "utf8")) as {
			findings?: FindingRecord[];
		};
		return Array.isArray(doc.findings) ? doc.findings : [];
	} catch (err) {
		logger.warn("Failed to read manual-review appendix; treating as empty", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
		return [];
	}
}

/**
 * Shared gate primitive: mark every non-exploited vuln for which `shouldGate`
 * holds as `unverified_out_of_scope` (mutating `vulns` in place). An `exploited`
 * finding is never touched — a live PoC overrides missing source / a failed
 * validation lane. Both the coverage gate (T3) and the failed-lane gate (T5)
 * route through here so the demotion path stays identical.
 */
function markUnverifiedWhere(
	vulns: NormalizedVuln[],
	shouldGate: (vuln: NormalizedVuln) => boolean,
): void {
	for (const vuln of vulns) {
		if (vuln.disposition === "exploited") continue;
		// Already terminal (e.g. screen-rejected) — keep its specific disposition.
		if (isGatedOut(vuln.disposition)) continue;
		if (shouldGate(vuln)) vuln.disposition = "unverified_out_of_scope";
	}
}

/**
 * Coverage gate (T3): a finding whose enforcing tier was NOT in the analyzed
 * source AND that was not live-exploited is marked `unverified_out_of_scope`.
 * Mutates `vulns` in place. No manifest ⇒ no-op (full-stack scans must not
 * regress).
 */
function applyCoverageGate(
	deliverablesPath: string,
	vulns: NormalizedVuln[],
	logger: ActivityLogger,
): void {
	const manifest = readCoverageManifest(deliverablesPath, logger);
	if (!manifest) return;
	markUnverifiedWhere(
		vulns,
		(vuln) => !isTierCovered(manifest, enforcingTier(vuln.category, manifest)),
	);
}

/**
 * Failed-lane gate (T5): when a category's exploitation (validation) lane FAILED
 * (the exploit agent threw), its non-exploited findings were never validated and
 * must not pass through as `firm`/`tentative` as if confirmed. Demote them to
 * `unverified_out_of_scope` — the SAME exclusion + manual-review-appendix path as
 * the coverage gate. An `exploited` finding still stands (a live PoC needs no
 * lane). Absence of `validation_lane_status.json` ⇒ no-op (no regression).
 */
function applyFailedLaneGate(
	deliverablesPath: string,
	vulns: NormalizedVuln[],
	logger: ActivityLogger,
): void {
	const laneStatus = readLaneStatus(deliverablesPath, logger);
	markUnverifiedWhere(vulns, (vuln) => laneStatus[vuln.category] === "failed");
}

/**
 * Premise gate (T2): an `exploited` finding whose escalation premise is invalid
 * (`premise_valid === false` — e.g. an authz "escalation" only ever performed by a
 * privileged identity) is not a proven exploit. Demote it to the terminal
 * `exploited_privileged` (→ appendix). A finding with `premise_valid` unset/true
 * keeps its exploited gate-bypass unchanged. Mutates in place. The signal is set
 * upstream (multi-identity, T9, deferred); until then this is a no-op hook.
 */
function applyPremiseGate(vulns: NormalizedVuln[]): void {
	for (const vuln of vulns) {
		if (vuln.disposition === "exploited" && vuln.premise_valid === false) {
			vuln.disposition = "exploited_privileged";
		}
	}
}

/**
 * Tag scaffolding scope (T2), apply the coverage + failed-lane + premise gates, map
 * to `FindingRecord`s, run the coherence gate (T8), then return ONLY the EMITTED set
 * (gated-out records are written to the manual-review appendix). The returned type
 * stays `FindingRecord[]` so `collectFindings`'s synchronous callers are untouched.
 */
export function gateAndMapFindings(
	deliverablesPath: string,
	vulns: NormalizedVuln[],
	logger: ActivityLogger,
): FindingRecord[] {
	tagScope(vulns);
	applyCoverageGate(deliverablesPath, vulns, logger);
	applyFailedLaneGate(deliverablesPath, vulns, logger);
	applyPremiseGate(vulns);

	const records = toFindingRecords(vulns);
	const demoted = applyCoherenceGate(records);
	if (demoted > 0) {
		logger.info("Coherence gate demoted incoherent findings", { demoted });
	}
	const appendix = records.filter((r) => isGatedOut(r.disposition));
	const emitted = records.filter((r) => !isGatedOut(r.disposition));
	writeManualReviewAppendix(deliverablesPath, appendix, logger);
	return emitted;
}
