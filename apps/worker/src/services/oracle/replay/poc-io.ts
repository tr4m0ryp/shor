// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Disk I/O for the oracle: parse the exploit agents' `{category}_poc.json`
 * sidecars into validated {@link Poc}s, and read/write the authoritative
 * `oracle_dispositions.json` (`{ id -> disposition }`). Every read is
 * best-effort — a missing or malformed file is skipped, never fatal.
 */

import fs from "node:fs";
import path from "node:path";
import { canonicalVulnId } from "../../../job/findings/evidence.js";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import type {
	ExpectedSignal,
	OracleDisposition,
	Poc,
	PocKind,
	PocRequest,
	SignalType,
} from "./types.js";

/** Suffix every per-category PoC sidecar shares (`injection_poc.json`, …). */
const POC_SUFFIX = "_poc.json";
/** The authoritative, machine-readable replay verdict map. */
export const ORACLE_DISPOSITIONS_FILE = "oracle_dispositions.json";

const POC_KINDS: ReadonlySet<string> = new Set<PocKind>(["http", "browser", "oob"]);
const SIGNAL_TYPES: ReadonlySet<string> = new Set<SignalType>(["status", "reflection", "oob", "data"]);
const DISPOSITIONS: ReadonlySet<string> = new Set<OracleDisposition>(["exploited", "blocked", "not_replayable"]);

function asRecord(v: unknown): Record<string, unknown> | undefined {
	return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function asStringMap(v: unknown): Record<string, string> | undefined {
	const r = asRecord(v);
	if (!r) return undefined;
	const out: Record<string, string> = {};
	for (const [k, val] of Object.entries(r)) {
		if (typeof val === "string") out[k] = val;
	}
	return Object.keys(out).length > 0 ? out : undefined;
}

function parseRequest(v: unknown): PocRequest | undefined {
	const r = asRecord(v);
	if (!r) return undefined;
	const url = typeof r.url === "string" ? r.url : "";
	if (url === "") return undefined;
	const method = typeof r.method === "string" && r.method.trim() !== "" ? r.method : "GET";
	const out: PocRequest = { method, url };
	const headers = asStringMap(r.headers);
	if (headers) out.headers = headers;
	if (typeof r.body === "string") out.body = r.body;
	return out;
}

function parseSignal(v: unknown): ExpectedSignal | undefined {
	const r = asRecord(v);
	if (!r) return undefined;
	if (typeof r.type !== "string" || !SIGNAL_TYPES.has(r.type)) return undefined;
	if (typeof r.match !== "string" && typeof r.match !== "number") return undefined;
	return { type: r.type as SignalType, match: r.match };
}

/** Validate one raw PoC object; returns undefined when it cannot be replayed. */
export function parsePoc(v: unknown): Poc | undefined {
	const r = asRecord(v);
	if (!r) return undefined;
	const id = typeof r.id === "string" ? r.id.trim() : "";
	if (id === "") return undefined;
	if (typeof r.kind !== "string" || !POC_KINDS.has(r.kind)) return undefined;
	const expected = parseSignal(r.expected_signal);
	if (!expected) return undefined;
	const poc: Poc = { id, kind: r.kind as PocKind, expected_signal: expected };
	const req = parseRequest(r.request);
	if (req) poc.request = req;
	if (typeof r.browser_script === "string") poc.browser_script = r.browser_script;
	if (r.safe === true) poc.safe = true;
	return poc;
}

/** Read + validate every `{category}_poc.json` in the deliverables directory. */
export function readPocFiles(deliverablesPath: string, logger: ActivityLogger): Poc[] {
	let names: string[];
	try {
		names = fs.readdirSync(deliverablesPath);
	} catch {
		return [];
	}
	const out: Poc[] = [];
	for (const name of names.filter((n) => n.endsWith(POC_SUFFIX))) {
		const full = path.join(deliverablesPath, name);
		try {
			const parsed: unknown = JSON.parse(fs.readFileSync(full, "utf8"));
			if (!Array.isArray(parsed)) {
				logger.warn("Oracle PoC file is not a JSON array; skipping", { file: name });
				continue;
			}
			for (const item of parsed) {
				const poc = parsePoc(item);
				if (poc) out.push(poc);
				else logger.warn("Oracle PoC entry malformed; skipping", { file: name });
			}
		} catch (err) {
			logger.warn("Failed to read/parse oracle PoC file; skipping", {
				file: name,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}
	return out;
}

/** Write the authoritative `{ id -> disposition }` map for `applyOracleDispositions`. */
export function writeDispositions(
	deliverablesPath: string,
	map: Map<string, OracleDisposition>,
	logger: ActivityLogger,
): void {
	const obj: Record<string, OracleDisposition> = {};
	for (const [id, disp] of map) obj[id] = disp;
	try {
		fs.writeFileSync(path.join(deliverablesPath, ORACLE_DISPOSITIONS_FILE), `${JSON.stringify(obj, null, 2)}\n`);
	} catch (err) {
		logger.warn("Failed to write oracle dispositions; replay verdicts not persisted", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

/** Read `oracle_dispositions.json` into a canonical-id-keyed verdict map. */
export function readDispositions(
	deliverablesPath: string,
	logger: ActivityLogger,
): Map<string, OracleDisposition> {
	const out = new Map<string, OracleDisposition>();
	const full = path.join(deliverablesPath, ORACLE_DISPOSITIONS_FILE);
	try {
		if (!fs.existsSync(full)) return out;
		const r = asRecord(JSON.parse(fs.readFileSync(full, "utf8")));
		if (!r) return out;
		for (const [id, disp] of Object.entries(r)) {
			if (typeof disp === "string" && DISPOSITIONS.has(disp)) {
				out.set(canonicalVulnId(id), disp as OracleDisposition);
			}
		}
	} catch (err) {
		logger.warn("Failed to read oracle dispositions; markdown parse remains authoritative", {
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return out;
}

/**
 * Look up a verdict for a queue VULN-ID, tolerating ID drift: exact canonical
 * match first, then a trailing-number fallback (each map is per-scan, so the
 * numeric suffix is a safe discriminator) — mirrors `lookupEvidence`.
 */
export function lookupDisposition(
	map: Map<string, OracleDisposition>,
	id: string,
): OracleDisposition | undefined {
	const canon = canonicalVulnId(id);
	const direct = map.get(canon);
	if (direct) return direct;
	const num = canon.match(/(\d+)$/)?.[1];
	if (!num) return undefined;
	for (const [key, disp] of map) {
		if (key.match(/(\d+)$/)?.[1] === num) return disp;
	}
	return undefined;
}
