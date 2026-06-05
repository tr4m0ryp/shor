// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Findings emission for the Cloud Run Job (ADR-051): after the scan pipeline,
 * read the structured deliverables, map them into `FindingRecord`s, attach the
 * attack-surface document, and POST the lot to the dashboard sink.
 *
 * Resilient by design: every read is best-effort (missing files are skipped),
 * and a final status is always POSTed — `completed` on success, `failed` when
 * the pipeline threw. The POST itself never throws (see `postFindings`).
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { lookupEvidence, readEvidence } from "./evidence.js";
import { gateAndMapFindings, readManualReviewAppendix } from "./gating.js";
import { FINDING_CATEGORIES, readQueues } from "./queue.js";
import { postFindings, readSinkConfig } from "./sink.js";
import type {
	FindingCategory,
	FindingRecord,
	FindingsSinkPayload,
} from "./types.js";

const ATTACK_SURFACE_FILE = "attack_surface_scenarios.json";

/** Read + parse the attack-surface document, or undefined if absent/bad. */
function readAttackSurface(
	deliverablesPath: string,
	logger: ActivityLogger,
): Record<string, unknown> | undefined {
	const filePath = path.join(deliverablesPath, ATTACK_SURFACE_FILE);
	try {
		if (!fs.existsSync(filePath)) return undefined;
		const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
		return undefined;
	} catch (err) {
		logger.warn("Failed to read/parse attack surface; skipping", {
			filePath,
			error: err instanceof Error ? err.message : String(err),
		});
		return undefined;
	}
}

const IMPROVED_FINDINGS_FILE = "improved_findings.json";

/**
 * Overlay the Sinas "improvement findings" pass (cli-finalization.ts) onto the
 * mapped records: if `improved_findings.json` exists, replace each record's prose
 * fields (title/evidence/missing_defense/remediation/safe_poc/repro_steps) with
 * the cleaned versions, matched by id. Identity (fingerprint, severity, cwe,
 * location, category) is never changed. No-op when the file is absent.
 */
function applyImprovedText(
	deliverablesPath: string,
	records: FindingRecord[],
	logger: ActivityLogger,
): FindingRecord[] {
	const file = path.join(deliverablesPath, IMPROVED_FINDINGS_FILE);
	if (!fs.existsSync(file)) return records;
	try {
		const doc = JSON.parse(fs.readFileSync(file, "utf8")) as {
			findings?: Array<Record<string, unknown>>;
		};
		const byId = new Map((doc.findings ?? []).map((f) => [String(f.id), f]));
		return records.map((r) => {
			const imp = byId.get(String(r.id));
			if (!imp) return r;
			const overlay: Partial<FindingRecord> & { title?: string } = {};
			if (typeof imp.title === "string" && imp.title.trim()) overlay.title = imp.title;
			if (typeof imp.evidence === "string" && imp.evidence.trim()) overlay.evidence = imp.evidence;
			if (typeof imp.missing_defense === "string" && imp.missing_defense.trim())
				overlay.missing_defense = imp.missing_defense;
			if (typeof imp.remediation === "string" && imp.remediation.trim()) overlay.remediation = imp.remediation;
			if (typeof imp.safe_poc === "string" && imp.safe_poc.trim()) overlay.safe_poc = imp.safe_poc;
			if (Array.isArray(imp.repro_steps) && imp.repro_steps.length)
				overlay.repro_steps = imp.repro_steps.map((s) => String(s));
			return { ...r, ...overlay };
		});
	} catch (err) {
		logger.warn("Failed to apply improved findings; using raw", {
			error: err instanceof Error ? err.message : String(err),
		});
		return records;
	}
}

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
 * Build the EMITTED finding records from the deliverables: read each category's
 * queue, enrich with the exploitation-evidence disposition + prose, apply the
 * coverage gate, then map to §6.1.
 *
 * Coverage gate (T3): a finding whose enforcing tier was NOT in the analyzed
 * source AND that was not live-exploited cannot be verified from this scan. It
 * is marked `unverified_out_of_scope`, EXCLUDED from the returned (emitted) set,
 * and written to a separate manual-review appendix deliverable. Exploited
 * findings are NEVER gated (a live PoC overrides missing source). When no
 * manifest exists, no gating is applied (full-stack scans must not regress).
 *
 * The return type stays `FindingRecord[]` (the emitted set) so the synchronous
 * callers in cli-finalization.ts are untouched.
 */
export function collectFindings(
	deliverablesPath: string,
	logger: ActivityLogger,
): FindingRecord[] {
	const vulns = readQueues(deliverablesPath, logger);

	// Enrich each vuln with its evidence disposition + prose (per category). The
	// lookup is drift-tolerant (canonical ID + trailing-number fallback) — a strict
	// match silently dropped every live-confirmed finding to `queued` → `firm`.
	const evidenceByCategory = new Map(
		FINDING_CATEGORIES.map((c) => [
			c,
			readEvidence(deliverablesPath, c, logger),
		]),
	);
	for (const vuln of vulns) {
		const map = evidenceByCategory.get(vuln.category);
		const entry = map ? lookupEvidence(map, vuln.id) : undefined;
		if (entry) {
			vuln.disposition = entry.disposition;
			vuln.evidenceText = entry.text;
		}
	}

<<<<<<< HEAD
	// Observability: a category whose evidence file HAS entries but matched NONE of
	// its queue IDs is the exact silent-failure signature behind the "nothing ever
	// confirmed" regression. Warn loudly per category and once in aggregate so the
	// drift is visible in the run logs instead of disappearing into `firm`.
	for (const category of FINDING_CATEGORIES) {
		const map = evidenceByCategory.get(category);
		if (!map || map.size === 0) continue;
		const catVulns = vulns.filter((v) => v.category === category);
		const matched = catVulns.filter((v) => v.disposition === "exploited" || v.disposition === "blocked").length;
		const exploited = catVulns.filter((v) => v.disposition === "exploited").length;
		if (catVulns.length > 0 && matched === 0) {
			logger.warn(
				"Evidence present but matched ZERO queue findings — disposition drift; all stay queued/firm",
				{
					category,
					evidenceEntries: map.size,
					evidenceIds: [...map.keys()],
					queueIds: catVulns.map((v) => v.id),
				},
			);
		} else {
			logger.info("Evidence matched", {
				category,
				evidenceEntries: map.size,
				queueFindings: catVulns.length,
				matched,
				exploited,
			});
=======
	// Adversarial screen rejections (T4): the screen agent refuted these hypotheses
	// before exploitation. Mark the matching queue entry (or synthesize one when the
	// raw queue no longer carries it) `unverified_screen_rejected` so the gate routes
	// it to the manual-review appendix and OUT of the emitted set — exactly like
	// `unverified_out_of_scope`. A live PoC still wins: an `exploited` finding is
	// never demoted.
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
>>>>>>> agent/agent-a06e840a35c31d20f
		}
	}

	// Apply the coverage gate, map to §6.1, and keep only the EMITTED set (gated-
	// out findings are routed to the manual-review appendix inside this call).
	const emitted = gateAndMapFindings(deliverablesPath, vulns, logger);

	return applyImprovedText(deliverablesPath, emitted, logger);
}

/**
 * Emit findings to the dashboard sink. Always POSTs a final status. `failed`
 * forces an empty findings array (the pipeline did not complete cleanly), but a
 * best-effort read is still attempted for whatever partial deliverables exist.
 *
 * Returns `true` if the POST succeeded (2xx) or there was nothing to do because
 * the sink is unconfigured; `false` if a configured POST failed.
 */
export async function reportFindings(
	deliverablesPath: string,
	scanId: string,
	status: "completed" | "failed" | "running",
	logger: ActivityLogger,
): Promise<boolean> {
	const sink = readSinkConfig(scanId);
	if (!sink) {
		logger.warn("Findings sink not configured; skipping emission", {
			scanId,
			status,
		});
		return true;
	}

	let findings: FindingRecord[] = [];
	let attackSurface: Record<string, unknown> | undefined;
	try {
		findings = collectFindings(deliverablesPath, logger);
		// Surface the gated-out manual-review findings to the DASHBOARD as well —
		// they carry the `unverified_out_of_scope` disposition, so the UI segregates
		// them behind a "manual review" filter and they never enter the attack
		// surface. Other `collectFindings` callers (e.g. Sinas finalize) stay clean.
		const manualReview = readManualReviewAppendix(deliverablesPath, logger);
		if (manualReview.length > 0) findings = [...findings, ...manualReview];
		attackSurface = readAttackSurface(deliverablesPath, logger);
	} catch (err) {
		// Mapping should not throw, but never let it block the status POST.
		logger.error("Findings collection failed; posting status only", {
			scanId,
			error: err instanceof Error ? err.message : String(err),
		});
		findings = [];
	}

	const payload: FindingsSinkPayload = {
		findings,
		status,
		...(attackSurface !== undefined && { attackSurface }),
	};

	logger.info("Emitting findings to dashboard sink", {
		scanId,
		status,
		findingsCount: findings.length,
		hasAttackSurface: attackSurface !== undefined,
	});

	return postFindings(sink, payload, logger);
}
