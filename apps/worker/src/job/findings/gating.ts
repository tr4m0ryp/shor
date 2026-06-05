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
import { readLaneStatus } from "./lane-status.js";
import { toFindingRecords } from "./mapping.js";
import type {
	FindingCategory,
	FindingRecord,
	NormalizedVuln,
} from "./types.js";

export const MANUAL_REVIEW_APPENDIX_FILE = "manual_review_appendix.json";

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
 * (sinas-finalization.ts). Absence MUST disable gating entirely.
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
 * Persist the gated-out (`unverified_out_of_scope`) findings to a separate
 * deliverable so a reviewer can see what was set aside. Best-effort: a write
 * failure never blocks emission. No file is written when nothing was gated out,
 * keeping the no-manifest / full-coverage path identical to before.
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
			disposition: "unverified_out_of_scope",
			note:
				"Findings that could not be verified from this scan — either the " +
				"enforcing tier was not in the analyzed source, or the category's " +
				"validation lane failed — and that were not live-confirmed. Excluded " +
				"from the emitted attack surface; review manually.",
			findings: appendix,
		};
		fs.writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`);
		logger.info("Wrote manual-review appendix (out-of-scope unconfirmed)", {
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
	for (const vuln of vulns) {
		if (vuln.disposition === "exploited") continue;
		if (!isTierCovered(manifest, enforcingTier(vuln.category, manifest))) {
			vuln.disposition = "unverified_out_of_scope";
		}
	}
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
	for (const vuln of vulns) {
		if (vuln.disposition === "exploited") continue;
		if (laneStatus[vuln.category] === "failed") {
			vuln.disposition = "unverified_out_of_scope";
		}
	}
}

/**
 * Apply the coverage gate + the failed-lane gate, then map to `FindingRecord`s
 * and return ONLY the EMITTED set (gated-out records are written to the manual-
 * review appendix). The returned type stays `FindingRecord[]` so
 * `collectFindings`'s synchronous callers are untouched.
 */
export function gateAndMapFindings(
	deliverablesPath: string,
	vulns: NormalizedVuln[],
	logger: ActivityLogger,
): FindingRecord[] {
	applyCoverageGate(deliverablesPath, vulns, logger);
	applyFailedLaneGate(deliverablesPath, vulns, logger);

	const records = toFindingRecords(vulns);
	const appendix = records.filter(
		(r) => r.disposition === "unverified_out_of_scope",
	);
	const emitted = records.filter(
		(r) => r.disposition !== "unverified_out_of_scope",
	);
	writeManualReviewAppendix(deliverablesPath, appendix, logger);
	return emitted;
}
