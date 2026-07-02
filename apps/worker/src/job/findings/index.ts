// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
import { clusterFindings } from "../../services/dedup-judge/index.js";
// Import the router LEAF (not the fp-panel index) so there is no import cycle:
// fp-panel/index imports collectFindings, but the router imports neither.
import { applyFpRefuteVerdicts } from "../../services/fp-panel/router.js";
import { gradeFindings } from "../../services/grader/index.js";
import { applyOracleDispositions } from "../../services/oracle/index.js";
import { applyScreenVerdicts } from "../../services/screen-verdicts/index.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { clusterDeterministic } from "./dedup-collapse.js";
import { demoteDevCredentials } from "./dev-credential-guard.js";
import { lookupEvidence, readEvidence } from "./evidence.js";
import { gateAndMapFindings, readManualReviewAppendix } from "./gating.js";
import { FINDING_CATEGORIES, readQueues } from "./queue.js";
import { postFindings, readSinkConfig } from "./sink.js";
import type { FindingRecord, FindingsSinkPayload } from "./types.js";

const ATTACK_SURFACE_FILE = "attack_surface_scenarios.json";
const REPORT_JSON_FILE = "report.json";

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

/**
 * Read the structured finalized report (`report.json`, written by
 * cli-finalization stage 3) so `emitFindings` can POST it through the sink — the
 * dashboard serves it from the DB now that the Sinas report store is decommissioned.
 */
function readReport(
	deliverablesPath: string,
	logger: ActivityLogger,
): Record<string, unknown> | undefined {
	const filePath = path.join(deliverablesPath, REPORT_JSON_FILE);
	try {
		if (!fs.existsSync(filePath)) return undefined;
		const parsed: unknown = JSON.parse(fs.readFileSync(filePath, "utf8"));
		if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
			return parsed as Record<string, unknown>;
		}
		return undefined;
	} catch (err) {
		logger.warn("Failed to read/parse finalized report; skipping", {
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
			if (typeof imp.title === "string" && imp.title.trim())
				overlay.title = imp.title;
			if (typeof imp.evidence === "string" && imp.evidence.trim())
				overlay.evidence = imp.evidence;
			if (typeof imp.missing_defense === "string" && imp.missing_defense.trim())
				overlay.missing_defense = imp.missing_defense;
			if (typeof imp.remediation === "string" && imp.remediation.trim())
				overlay.remediation = imp.remediation;
			if (typeof imp.safe_poc === "string" && imp.safe_poc.trim())
				overlay.safe_poc = imp.safe_poc;
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
 * Returns the emitted set. ASYNC: the dedup-judge pass (T12, opt-in) runs an LLM
 * per finding, so this and its callers await it; when the judge is disabled the
 * pass is an immediate identity no-op (the emitted set is byte-for-byte unchanged).
 */
export async function collectFindings(
	deliverablesPath: string,
	logger: ActivityLogger,
	opts?: { analyzedSourceRoot?: string },
): Promise<FindingRecord[]> {
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

	// Adversarial screen verdicts (T4) then oracle adjudication (T13) — ordered
	// pass-through, both operating on the normalized queue BEFORE the emission gate.
	// `applyScreenVerdicts` stamps screen-refuted hypotheses
	// `unverified_screen_rejected` (its default preserves today's behavior: the gate
	// routes them to the manual-review appendix and OUT of the emitted set, and a
	// live `exploited` PoC is never demoted). `applyOracleDispositions` is an
	// identity no-op until task 013 fills it. Both mutate `vulns` in place.
	applyScreenVerdicts(vulns, deliverablesPath, logger);
	applyOracleDispositions(vulns, deliverablesPath, logger);
	// Adversarial FP-refute panel (T2, opt-in): demote any confirmed finding a
	// source-aware skeptic panel majority-refuted to `refuted_on_review` → appendix.
	// No-op when the panel did not run (no verdicts file).
	applyFpRefuteVerdicts(vulns, deliverablesPath, logger);

	// Observability: a category whose evidence file HAS entries but matched NONE of
	// its queue IDs is the exact silent-failure signature behind the "nothing ever
	// confirmed" regression. Warn loudly per category and once in aggregate so the
	// drift is visible in the run logs instead of disappearing into `firm`.
	for (const category of FINDING_CATEGORIES) {
		const map = evidenceByCategory.get(category);
		if (!map || map.size === 0) continue;
		const catVulns = vulns.filter((v) => v.category === category);
		const matched = catVulns.filter(
			(v) => v.disposition === "exploited" || v.disposition === "blocked",
		).length;
		const exploited = catVulns.filter(
			(v) => v.disposition === "exploited",
		).length;
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
		}
	}

	// Apply the coverage gate, map to §6.1, and keep only the EMITTED set (gated-
	// out findings are routed to the manual-review appendix inside this call).
	const emitted = gateAndMapFindings(
		deliverablesPath,
		vulns,
		logger,
		opts?.analyzedSourceRoot,
	);
	const improved = applyImprovedText(deliverablesPath, emitted, logger);

	// Demote intentional dev/test credentials (committed scaffolding that production
	// overrides) from critical/high to low — a committed `// For local testing` key is
	// not a leaked production secret. Runs on the source root so a trailing dev-marker
	// comment on the cited line is seen. Pure; non-secret findings pass through.
	const guarded = demoteDevCredentials(improved, opts?.analyzedSourceRoot, logger);

	// Final emitted-set passes (ordered): cluster near-duplicates by root cause
	// (T12, async + opt-in), then grade. `gradeFindings` is an identity no-op today
	// (task 015); the dedup pass is identity unless the judge is enabled.
	const clustered = await clusterFindings(guarded, {
		deliverablesPath,
		logger,
	});
	// T4: the LLM judge is opt-in. When it did NOT run (no `cluster_id` on any
	// record), stamp a deterministic `cluster_id` so the dashboard's group-by-cluster
	// always collapses duplicates. Pure, never drops; the judge's ids win when present.
	const grouped = clustered.some((f) => f.cluster_id)
		? clustered
		: clusterDeterministic(clustered);
	return gradeFindings(grouped, { deliverablesPath, logger });
}

/**
 * Emit findings to the dashboard sink. Always POSTs a final status. `failed`
 * forces an empty findings array (the pipeline did not complete cleanly), but a
 * best-effort read is still attempted for whatever partial deliverables exist.
 *
 * Returns `true` if the POST succeeded (2xx) or there was nothing to do because
 * the sink is unconfigured; `false` if a configured POST failed.
 */
/**
 * Serialize concurrent emissions. The pipeline calls {@link reportFindings} in
 * EVERY agent's `finally`, so at full group width up to N agents emit near-
 * simultaneously. The reads are safe (each agent owns its files), but the sink
 * POST should not be thrashed by N overlapping cumulative payloads — chain them
 * so they post in order. A failure never breaks the chain.
 */
let emitChain: Promise<unknown> = Promise.resolve();

export function reportFindings(
	deliverablesPath: string,
	scanId: string,
	status: "completed" | "failed" | "running",
	logger: ActivityLogger,
): Promise<boolean> {
	const run = emitChain.then(() =>
		emitFindings(deliverablesPath, scanId, status, logger),
	);
	emitChain = run.then(
		() => undefined,
		() => undefined,
	);
	return run;
}

async function emitFindings(
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
	let report: Record<string, unknown> | undefined;
	try {
		// Enable cite-line verification (T3) by handing the mapper the cloned-target
		// source root (the same path the worker resolves it from, env.ts). Fail-open:
		// if the path is unset/unreadable, the verifier simply skips (behavior unchanged).
		const analyzedSourceRoot = process.env.SHOR_REPO_PATH ?? "/work/repo";
		findings = await collectFindings(deliverablesPath, logger, {
			analyzedSourceRoot,
		});
		// Surface the gated-out manual-review findings to the DASHBOARD as well —
		// they carry the `unverified_out_of_scope` disposition, so the UI segregates
		// them behind a "manual review" filter and they never enter the attack
		// surface. Other `collectFindings` callers (e.g. Sinas finalize) stay clean.
		const manualReview = readManualReviewAppendix(deliverablesPath, logger);
		if (manualReview.length > 0) findings = [...findings, ...manualReview];
		attackSurface = readAttackSurface(deliverablesPath, logger);
		report = readReport(deliverablesPath, logger);
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
		...(report !== undefined && { report }),
	};

	logger.info("Emitting findings to dashboard sink", {
		scanId,
		status,
		findingsCount: findings.length,
		hasAttackSurface: attackSurface !== undefined,
		hasReport: report !== undefined,
	});

	return postFindings(sink, payload, logger);
}
