// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Parse the per-category exploitation evidence markdown.
 *
 * Each evidence file (e.g. `injection_exploitation_evidence.md`) has two top-
 * level sections produced by the exploit prompts:
 *   `## Successfully Exploited Vulnerabilities`        → disposition `exploited`
 *   `## Potential Vulnerabilities (Validation Blocked)`→ disposition `blocked`
 * Within each, findings appear as `### <VULN-ID>: <title>` blocks. We extract
 * the per-ID prose and its disposition so the mapper can promote a queued
 * hypothesis to a proven finding and attach the evidence text.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { FindingCategory } from "./types.js";

/** Evidence filenames keyed by category (mirrors DELIVERABLE_FILENAMES). */
const EVIDENCE_FILES: Record<FindingCategory, string> = {
	injection: "injection_exploitation_evidence.md",
	xss: "xss_exploitation_evidence.md",
	auth: "auth_exploitation_evidence.md",
	ssrf: "ssrf_exploitation_evidence.md",
	authz: "authz_exploitation_evidence.md",
};

export interface EvidenceEntry {
	disposition: "exploited" | "blocked";
	text: string;
}

type Disposition = "exploited" | "blocked";

/** Map a `## ` section heading to a disposition, or undefined if unrelated. */
function dispositionForHeading(heading: string): Disposition | undefined {
	const h = heading.toLowerCase();
	if (h.includes("successfully exploited")) return "exploited";
	if (h.includes("validation blocked") || h.includes("potential vulnerab"))
		return "blocked";
	return undefined;
}

/** Extract the `<VULN-ID>` from a `### ID: title` line, or undefined. */
function vulnIdFromSubheading(line: string): string | undefined {
	// `### INJ-VULN-01: SQLi in /search` → `INJ-VULN-01`
	const m = line.match(/^###\s+([A-Za-z0-9_-]+)\s*[:—-]/);
	return m?.[1];
}

/**
 * Parse one evidence markdown body into a per-VULN-ID disposition + prose map.
 * `exploited` wins over `blocked` if an ID somehow appears under both.
 */
export function parseEvidenceMarkdown(
	body: string,
): Map<string, EvidenceEntry> {
	const result = new Map<string, EvidenceEntry>();
	const lines = body.split(/\r?\n/);

	let section: Disposition | undefined;
	let currentId: string | undefined;
	let buffer: string[] = [];

	const flush = (): void => {
		if (currentId && section) {
			const text = buffer.join("\n").trim();
			const existing = result.get(currentId);
			// exploited beats blocked; otherwise first-seen wins.
			if (!existing || (existing.disposition === "blocked" && section === "exploited")) {
				result.set(currentId, { disposition: section, text });
			}
		}
		currentId = undefined;
		buffer = [];
	};

	for (const line of lines) {
		if (line.startsWith("## ")) {
			flush();
			section = dispositionForHeading(line.slice(3).trim());
			continue;
		}
		if (section && line.startsWith("### ")) {
			flush();
			currentId = vulnIdFromSubheading(line);
			buffer = [];
			continue;
		}
		if (currentId) buffer.push(line);
	}
	flush();
	return result;
}

/**
 * Read and parse the evidence markdown for one category. Missing/unreadable
 * files yield an empty map (best-effort).
 */
export function readEvidence(
	deliverablesPath: string,
	category: FindingCategory,
	logger: ActivityLogger,
): Map<string, EvidenceEntry> {
	const filePath = path.join(deliverablesPath, EVIDENCE_FILES[category]);
	try {
		if (!fs.existsSync(filePath)) return new Map();
		return parseEvidenceMarkdown(fs.readFileSync(filePath, "utf8"));
	} catch (err) {
		logger.warn("Failed to read evidence markdown; skipping", {
			filePath,
			error: err instanceof Error ? err.message : String(err),
		});
		return new Map();
	}
}
