// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * PII redaction for the scrub stage — names, emails, internal hostnames/URLs,
 * and tenant identifiers must be redacted before text is embedded, because
 * embeddings are invertible (Vec2Text ~92% — spec F12/R4).
 *
 * Chosen approach (task 003 stop-condition — documented, not skipped):
 * Presidio is a Python service and is NOT embeddable in this TS worker, so it
 * runs as an HTTP sidecar (the stock `presidio-analyzer` container) injected
 * via `SHOR_SCRUB_PRESIDIO_URL`. Only its *analyzer* is used — entity spans
 * come back over HTTP and the redaction itself happens here, so scanned text
 * never round-trips through a second anonymizer service.
 *
 * Layering:
 * - A deterministic builtin regex layer ALWAYS runs: emails, IPv4, URL
 *   authorities, internal hostnames, UUIDs (this codebase's tenant/project/
 *   scan identifiers are UUIDs).
 * - Presidio, when configured, runs IN ADDITION and contributes NER coverage
 *   (PERSON names etc.) the regex layer cannot express.
 * - If Presidio is configured but unreachable, the analyzer THROWS and the
 *   scrub fails closed — coverage never silently degrades. When it is not
 *   configured, the result's `piiEngine: "builtin"` tells callers exactly
 *   what ran, so high-liability writers (T2 global tier) can refuse to pool.
 */

import { ScrubEngineError, type PiiAnalyzer, type PiiEntity } from "./types.js";

interface BuiltinPattern {
	entityType: string;
	regex: RegExp;
}

/**
 * Deterministic PII patterns. Conservative direction: over-redaction of the
 * memory corpus is acceptable, leakage is not.
 */
const BUILTIN_PATTERNS: readonly BuiltinPattern[] = [
	{
		entityType: "EMAIL_ADDRESS",
		regex: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
	},
	{
		entityType: "IP_ADDRESS",
		regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
	},
	{
		// The authority of any URL (userinfo@host:port) — hostnames and inline
		// basic-auth credentials go together.
		entityType: "URL_AUTHORITY",
		regex: /(?<=\/\/)(?:[A-Za-z0-9._%+-]+(?::[^@\s/]*)?@)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*(?::\d+)?/g,
	},
	{
		// Bare internal hostnames outside URLs.
		entityType: "INTERNAL_HOSTNAME",
		regex: /\b[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)*\.(?:internal|local|localdomain|corp|intra|intranet|lan|svc|cluster\.local)\b/gi,
	},
	{
		// Tenant/project/scan identifiers in this platform are UUIDs.
		entityType: "TENANT_ID",
		regex: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
	},
];

/** What a redacted span is replaced with, e.g. `[REDACTED-EMAIL_ADDRESS]`. */
export function piiPlaceholder(entityType: string): string {
	return `[REDACTED-${entityType.toUpperCase().replace(/[^A-Z0-9_]/g, "_")}]`;
}

/** The always-on deterministic layer. Pure; safe to run anywhere. */
export function createBuiltinPiiAnalyzer(): PiiAnalyzer {
	return async (text) => {
		const entities: PiiEntity[] = [];
		for (const { entityType, regex } of BUILTIN_PATTERNS) {
			// Fresh RegExp per call: /g state must not leak across invocations.
			for (const match of text.matchAll(new RegExp(regex.source, regex.flags))) {
				const value = match[0];
				if (match.index !== undefined && value.length > 0) {
					entities.push({ entityType, start: match.index, end: match.index + value.length });
				}
			}
		}
		return entities;
	};
}

export interface PresidioOptions {
	timeoutMs?: number | undefined;
	/** Minimum Presidio confidence score to redact on (default 0.5). */
	scoreThreshold?: number | undefined;
	language?: string | undefined;
}

/**
 * Presidio analyzer sidecar client (`POST {baseUrl}/analyze`). Any transport
 * or shape failure throws {@link ScrubEngineError}: a configured-but-broken
 * Presidio must fail the scrub closed, never quietly drop NER coverage.
 */
export function createPresidioAnalyzer(baseUrl: string, opts: PresidioOptions = {}): PiiAnalyzer {
	const timeoutMs = opts.timeoutMs ?? 15_000;
	const threshold = opts.scoreThreshold ?? 0.5;
	const language = opts.language ?? "en";
	const endpoint = `${baseUrl.replace(/\/+$/, "")}/analyze`;
	return async (text) => {
		let res: Response;
		try {
			res = await fetch(endpoint, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ text, language }),
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			throw new ScrubEngineError("presidio", msg.length > 200 ? `${msg.slice(0, 200)}…` : msg);
		}
		if (!res.ok) throw new ScrubEngineError("presidio", `HTTP ${res.status}`);
		let rows: unknown;
		try {
			rows = await res.json();
		} catch {
			throw new ScrubEngineError("presidio", "non-JSON response");
		}
		if (!Array.isArray(rows)) throw new ScrubEngineError("presidio", "response is not an array");
		const entities: PiiEntity[] = [];
		for (const row of rows) {
			const r = row as Record<string, unknown>;
			const start = r["start"];
			const end = r["end"];
			const score = typeof r["score"] === "number" ? r["score"] : 0;
			if (typeof start !== "number" || typeof end !== "number" || end <= start) continue;
			if (score < threshold) continue;
			entities.push({ entityType: String(r["entity_type"] ?? "PII"), start, end, score });
		}
		return entities;
	};
}
