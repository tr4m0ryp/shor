// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Read the per-category exploitation queues from the deliverables directory.
 *
 * Each queue is `{ "vulnerabilities": [ ... ] }` (the queue-validation wrapper).
 * Field names differ per category (see the vuln prompts'
 * `exploitation_queue_format`), so we keep the raw object and let the mapper
 * resolve the category-specific location/cwe fields.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { FindingCategory, NormalizedVuln, RawQueue } from "./types.js";

/** Queue filenames keyed by category (mirrors queue-validation/config.ts). */
export const QUEUE_FILES: Record<FindingCategory, string> = {
	injection: "injection_exploitation_queue.json",
	xss: "xss_exploitation_queue.json",
	auth: "auth_exploitation_queue.json",
	ssrf: "ssrf_exploitation_queue.json",
	authz: "authz_exploitation_queue.json",
	logic: "logic_exploitation_queue.json",
	"misconfig-web": "misconfig-web_exploitation_queue.json",
};

export const FINDING_CATEGORIES: readonly FindingCategory[] = [
	"injection",
	"xss",
	"auth",
	"ssrf",
	"authz",
	"logic",
	"misconfig-web",
] as const;

function readJsonSafe(filePath: string, logger: ActivityLogger): unknown {
	try {
		if (!fs.existsSync(filePath)) return undefined;
		return JSON.parse(fs.readFileSync(filePath, "utf8"));
	} catch (err) {
		logger.warn("Failed to read/parse queue file; skipping", {
			filePath,
			error: err instanceof Error ? err.message : String(err),
		});
		return undefined;
	}
}

/** Coerce a parsed queue's `vulnerabilities` into normalized entries. */
function normalizeQueue(
	category: FindingCategory,
	parsed: unknown,
): NormalizedVuln[] {
	const queue = (parsed ?? {}) as RawQueue;
	const items = Array.isArray(queue.vulnerabilities)
		? queue.vulnerabilities
		: [];

	const out: NormalizedVuln[] = [];
	for (let i = 0; i < items.length; i++) {
		const raw = items[i];
		if (raw === null || typeof raw !== "object") continue;
		const rec = raw as Record<string, unknown>;
		const id =
			typeof rec.ID === "string" && rec.ID.trim() !== ""
				? rec.ID
				: `${category.toUpperCase()}-VULN-${String(i + 1).padStart(2, "0")}`;
		out.push({
			category,
			id,
			raw: rec,
			disposition: "queued",
			evidenceText: "",
		});
	}
	return out;
}

/**
 * Read every per-category queue from `deliverablesPath`. Missing or malformed
 * files are skipped (best-effort), never fatal.
 */
export function readQueues(
	deliverablesPath: string,
	logger: ActivityLogger,
): NormalizedVuln[] {
	const all: NormalizedVuln[] = [];
	for (const category of FINDING_CATEGORIES) {
		const filePath = path.join(deliverablesPath, QUEUE_FILES[category]);
		const parsed = readJsonSafe(filePath, logger);
		if (parsed === undefined) continue;
		all.push(...normalizeQueue(category, parsed));
	}
	return all;
}
