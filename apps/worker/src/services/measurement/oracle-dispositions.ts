// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Best-effort read of the oracle adjudication deliverable (`oracle_dispositions.json`,
 * task 013) into an `id → OracleDisposition` map, used by the false-positive
 * proxy. Tolerant of the shapes task 013 might emit:
 *   - an array of `{ id, oracle_disposition | disposition }`,
 *   - `{ dispositions: [ ...same... ] }`,
 *   - a bare object map `{ "<id>": "blocked", ... }`.
 * An absent or malformed file yields an empty map (read-only, never fatal).
 */

import fs from "node:fs";
import path from "node:path";
import type { OracleDisposition } from "../../job/findings/types.js";
import type { ActivityLogger } from "../../types/activity-logger.js";

export const ORACLE_DISPOSITIONS_FILE = "oracle_dispositions.json";

const ORACLE_VALUES: readonly OracleDisposition[] = [
	"exploited",
	"blocked",
	"not_replayable",
];

function asOracle(value: unknown): OracleDisposition | undefined {
	return typeof value === "string" &&
		(ORACLE_VALUES as readonly string[]).includes(value)
		? (value as OracleDisposition)
		: undefined;
}

/** Walk a parsed `oracle_dispositions.json` value into the id → disposition map. */
function collect(parsed: unknown, out: Map<string, OracleDisposition>): void {
	if (Array.isArray(parsed)) {
		for (const entry of parsed) {
			if (!entry || typeof entry !== "object") continue;
			const rec = entry as Record<string, unknown>;
			const id = typeof rec.id === "string" ? rec.id.trim() : "";
			const disp = asOracle(rec.oracle_disposition) ?? asOracle(rec.disposition);
			if (id && disp) out.set(id, disp);
		}
		return;
	}
	if (!parsed || typeof parsed !== "object") return;
	const rec = parsed as Record<string, unknown>;
	if (Array.isArray(rec.dispositions)) {
		collect(rec.dispositions, out);
		return;
	}
	for (const [id, value] of Object.entries(rec)) {
		const disp = asOracle(value);
		if (id.trim() && disp) out.set(id.trim(), disp);
	}
}

/** Read `oracle_dispositions.json` from `deliverablesPath` (best-effort). */
export function readOracleDispositions(
	deliverablesPath: string,
	logger: ActivityLogger,
): Map<string, OracleDisposition> {
	const out = new Map<string, OracleDisposition>();
	const file = path.join(deliverablesPath, ORACLE_DISPOSITIONS_FILE);
	try {
		if (!fs.existsSync(file)) return out;
		collect(JSON.parse(fs.readFileSync(file, "utf8")), out);
	} catch (err) {
		logger.warn("Failed to read/parse oracle dispositions; skipping", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return out;
}
