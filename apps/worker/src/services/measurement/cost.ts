// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Best-effort cost inputs for the measurement harness: per-scan duration (and
 * tokens, when present) from the audit `session.json`. That file lives at the
 * workspace root with the deliverables nested beneath it, so we probe the
 * deliverables dir and its parent. Token totals are not persisted there today, so
 * tokens are read defensively (forward-compatible) and are usually null.
 *
 * Read-only; absence yields nulls and the report is still emitted.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";

const SESSION_FILE = "session.json";

/** Raw cost numbers pulled from a metrics file (nulls when unavailable). */
export interface CostInputs {
	source: string;
	durationMs: number | null;
	totalTokens: number | null;
}

function num(value: unknown): number | null {
	return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asObject(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

/**
 * Token total from a parsed session object, best-effort: an explicit aggregate
 * first, else the sum of per-attempt input+output tokens (a shape a future
 * session.json might carry). Returns null when no token data is present.
 */
function readTokens(data: Record<string, unknown>): number | null {
	const metrics = asObject(data.metrics);
	const explicit =
		num(metrics?.total_tokens) ??
		num(data.total_tokens) ??
		num(asObject(data.usage)?.total_tokens);
	if (explicit !== null) return explicit;

	const agents = asObject(metrics?.agents);
	if (!agents) return null;
	let sum = 0;
	let found = false;
	for (const agent of Object.values(agents)) {
		const attempts = asObject(agent)?.attempts;
		if (!Array.isArray(attempts)) continue;
		for (const att of attempts) {
			const t = asObject(att);
			if (!t) continue;
			const i = num(t.input_tokens);
			const o = num(t.output_tokens);
			if (i !== null || o !== null) {
				found = true;
				sum += (i ?? 0) + (o ?? 0);
			}
		}
	}
	return found ? sum : null;
}

/**
 * Read cost inputs from the first `session.json` found at `deliverablesPath` or
 * its parent. Returns null when none is readable.
 */
export function readCostInputs(
	deliverablesPath: string,
	logger: ActivityLogger,
): CostInputs | null {
	const candidates = [
		path.join(deliverablesPath, SESSION_FILE),
		path.join(deliverablesPath, "..", SESSION_FILE),
	];
	for (const file of candidates) {
		try {
			if (!fs.existsSync(file)) continue;
			const data = asObject(JSON.parse(fs.readFileSync(file, "utf8")));
			if (!data) continue;
			return {
				source: file,
				durationMs: num(asObject(data.metrics)?.total_duration_ms),
				totalTokens: readTokens(data),
			};
		} catch (err) {
			logger.warn("Failed to read/parse session metrics; skipping cost", {
				file,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return null;
}
