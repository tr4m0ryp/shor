// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Recon-driven target surface for the `{{TARGET_SURFACE}}` prompt slot.
 *
 * The bug this closes: the static target skill assumed the API is reverse-proxied
 * under `{{WEB_URL}}/api/`. When the API actually lives on a SEPARATE PORT (e.g.
 * an SPA on :80 and a Kestrel API on :8080), agents probed the SPA, got its
 * catch-all `index.html`, and wrongly concluded the backend was unreachable —
 * running no tools and fail-opening the screen.
 *
 * Recon already discovers the real services and records them (in
 * `recon_deliverable.md` and `coverage_manifest.json`), but only as prose, which
 * agents did not reliably act on. This extracts the live ORIGINS recon observed —
 * deterministically, no LLM — and the prompt presents them as the AUTHORITATIVE
 * probe surface, so every agent/voter targets the real service ports by default.
 */

import { fs, path } from "zx";

/** Recon artifacts (newest-first) that mention live service URLs. */
const SURFACE_SOURCES = [
	"recon_deliverable.md",
	"coverage_manifest.json",
	"pre_recon_deliverable.md",
] as const;

/** Cap the rendered list so a noisy deliverable can't bloat every prompt. */
const MAX_ORIGINS = 12;

/** `scheme://host[:port]` of a URL, or null when unparseable / non-http. */
function originOf(raw: string): string | null {
	try {
		const u = new URL(raw);
		if (u.protocol !== "http:" && u.protocol !== "https:") return null;
		return u.origin;
	} catch {
		return null;
	}
}

/** Hostname of a URL, or null. */
function hostOf(raw: string | undefined): string | null {
	if (!raw) return null;
	try {
		return new URL(raw).hostname;
	} catch {
		return null;
	}
}

/** Numeric port of an origin (default 80/443 by scheme) for stable sorting. */
function portOf(origin: string): number {
	try {
		const u = new URL(origin);
		if (u.port) return Number(u.port);
		return u.protocol === "https:" ? 443 : 80;
	} catch {
		return 0;
	}
}

/**
 * Render the authoritative target surface block: the distinct live origins recon
 * observed on the target host, one per line, sorted by port. Scoped to the
 * target host (origins on other hosts are out of scope). Returns `undefined`
 * when no recon artifact exists yet (e.g. during recon itself) — the prompt then
 * renders the neutral "(none)" sentinel and falls back to its generic guidance.
 */
export async function renderTargetSurface(
	deliverablesPath: string,
	webUrl: string | undefined,
): Promise<string | undefined> {
	const texts: string[] = [];
	for (const file of SURFACE_SOURCES) {
		const p = path.join(deliverablesPath, file);
		try {
			if (await fs.pathExists(p)) texts.push(await fs.readFile(p, "utf8"));
		} catch {
			// unreadable source — skip it
		}
	}
	if (texts.length === 0) return undefined;

	const targetHost = hostOf(webUrl);
	const origins = new Set<string>();
	const urlPattern = /https?:\/\/[^\s"'`)\]}<>,|\\]+/gi;
	for (const text of texts) {
		for (const match of text.matchAll(urlPattern)) {
			const origin = originOf(match[0]);
			if (origin === null) continue;
			// Scope to the target host when known: other hosts are out of scope.
			if (targetHost !== null && hostOf(origin) !== targetHost) continue;
			origins.add(origin);
		}
	}
	// Always include the primary origin so the list is never empty when webUrl is set.
	const primary = originOf(webUrl ?? "");
	if (primary !== null) origins.add(primary);

	if (origins.size === 0) return undefined;

	const sorted = [...origins].sort((a, b) => portOf(a) - portOf(b)).slice(0, MAX_ORIGINS);
	return sorted.map((o) => `- ${o}`).join("\n");
}
