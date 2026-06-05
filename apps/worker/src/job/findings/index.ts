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
import { readEvidence } from "./evidence.js";
import { gateAndMapFindings } from "./gating.js";
import { FINDING_CATEGORIES, readQueues } from "./queue.js";
import { postFindings, readSinkConfig } from "./sink.js";
import type { FindingRecord, FindingsSinkPayload } from "./types.js";

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
 * Overlay the Sinas "improvement findings" pass (sinas-finalization.ts) onto the
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
 * callers in sinas-finalization.ts are untouched.
 */
export function collectFindings(
	deliverablesPath: string,
	logger: ActivityLogger,
): FindingRecord[] {
	const vulns = readQueues(deliverablesPath, logger);

	// Enrich each vuln with its evidence disposition + prose (per category).
	const evidenceByCategory = new Map(
		FINDING_CATEGORIES.map((c) => [
			c,
			readEvidence(deliverablesPath, c, logger),
		]),
	);
	for (const vuln of vulns) {
		const entry = evidenceByCategory.get(vuln.category)?.get(vuln.id);
		if (entry) {
			vuln.disposition = entry.disposition;
			vuln.evidenceText = entry.text;
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
