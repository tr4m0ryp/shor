// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Firm-retry context: after the primary EXPLOIT_AGENTS phase, collect findings
 * that are still `blocked` or `queued` (i.e. emitted as `firm`/`tentative` but
 * never live-confirmed) and write a machine-readable context file so the retry
 * exploit agents know exactly which findings to target with alternative probes.
 *
 * Only categories that actually have retryable findings get a non-empty entry.
 * The retry agents read `firm_retry_context.json` and APPEND any newly-confirmed
 * findings to the existing evidence markdown — the normal `collectFindings` flow
 * then picks up the enriched evidence without any changes to the gating logic.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { lookupEvidence, readEvidence } from "./evidence.js";
import { FINDING_CATEGORIES, QUEUE_FILES, readQueues } from "./queue.js";
import type { FindingCategory } from "./types.js";

export const FIRM_RETRY_CONTEXT_FILE = "firm_retry_context.json";

/** Per-category retryable finding IDs, separated by failure mode. */
export interface CategoryRetryEntry {
	/** Evidence showed "Validation Blocked" for these IDs. */
	blocked: string[];
	/** Queue has these IDs but the evidence file has no matching entry. */
	queued: string[];
	/** Prose from each finding's evidence block (keyed by VULN-ID). */
	blocking_notes: Record<string, string>;
	/** Path to the existing evidence file so the retry agent can read + append. */
	evidence_file: string;
	/** Queue filename so the retry agent can read the original finding data. */
	queue_file: string;
}

export type FirmRetryContext = Partial<Record<FindingCategory, CategoryRetryEntry>>;

/**
 * Build the firm-retry context by comparing the per-category exploitation
 * queues against the evidence produced in the first exploit pass. Returns
 * only categories with at least one retryable finding.
 */
export function buildFirmRetryContext(
	deliverablesPath: string,
	logger: ActivityLogger,
): FirmRetryContext {
	const vulns = readQueues(deliverablesPath, logger);
	const context: FirmRetryContext = {};

	for (const category of FINDING_CATEGORIES) {
		const categoryVulns = vulns.filter((v) => v.category === category);
		if (categoryVulns.length === 0) continue;

		const evidenceMap = readEvidence(deliverablesPath, category, logger);

		const blocked: string[] = [];
		const queued: string[] = [];
		const blocking_notes: Record<string, string> = {};

		for (const vuln of categoryVulns) {
			const entry = evidenceMap.get(vuln.id);
			if (!entry) {
				// No evidence at all — the exploit agent produced no entry for this ID.
				queued.push(vuln.id);
			} else if (entry.disposition === "blocked") {
				blocked.push(vuln.id);
				if (entry.text.trim()) blocking_notes[vuln.id] = entry.text.trim();
			}
			// disposition === "exploited" → confirmed; skip.
		}

		if (blocked.length === 0 && queued.length === 0) continue;

		const evidenceFilename = `${category}_exploitation_evidence.md`;
		context[category] = {
			blocked,
			queued,
			blocking_notes,
			evidence_file: path.join(deliverablesPath, evidenceFilename),
			queue_file: path.join(deliverablesPath, QUEUE_FILES[category]),
		};
	}

	return context;
}

/**
 * Write `firm_retry_context.json` to `deliverablesPath`. Best-effort: a write
 * failure is logged and swallowed (it must never abort the pipeline). Returns
 * the categories that have retryable findings (so the pipeline can skip the
 * retry group entirely when the map is empty).
 */
export function writeFirmRetryContext(
	deliverablesPath: string,
	logger: ActivityLogger,
): FirmRetryContext {
	const ctx = buildFirmRetryContext(deliverablesPath, logger);
	const file = path.join(deliverablesPath, FIRM_RETRY_CONTEXT_FILE);
	try {
		fs.writeFileSync(file, `${JSON.stringify(ctx, null, 2)}\n`);
		const categories = Object.keys(ctx) as FindingCategory[];
		logger.info("Wrote firm-retry context", { file, categories });
	} catch (err) {
		logger.warn("Failed to write firm-retry context; retry phase will be skipped", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return ctx;
}

/**
 * True when the firm-retry context has at least one category with retryable
 * findings. Used by the pipeline to conditionally skip the retry group.
 */
export function hasFirmRetryTargets(ctx: FirmRetryContext): boolean {
	return Object.values(ctx).some(
		(entry) => entry && (entry.blocked.length > 0 || entry.queued.length > 0),
	);
}

/**
 * Return the set of categories present in the retry context (those that need
 * a retry pass). The pipeline uses this to decide which retry agents to skip.
 */
export function firmRetryCategories(ctx: FirmRetryContext): FindingCategory[] {
	return (Object.keys(ctx) as FindingCategory[]).filter(
		(cat) => ctx[cat] && (ctx[cat]!.blocked.length > 0 || ctx[cat]!.queued.length > 0),
	);
}
