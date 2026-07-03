// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Triage pre-gate — PURE decision logic (spec T14).
 *
 * Two deterministic deciders (`gateTarget`, `gateCategory`) plus a coarse recon-text
 * deriver (`deriveCategorySignals`) so a caller can produce {@link CategorySignal}s
 * from a recon blob without an LLM. Every decider BIASES TO SCAN on missing/ambiguous
 * signal — the only `skip` is when a probe actually ran and found nothing. Nothing
 * here logs or performs IO; the orchestrator (`index.ts`) owns logging + the flag.
 */

import type { FindingCategory } from "../../job/findings/types.js";
import type {
	CategorySignal,
	TargetSignal,
	TriageConfig,
	TriageVerdict,
} from "./types.js";

/** Default flag state: gate OFF. A stock scan (no `SHOR_TRIAGE_GATE`) is unchanged. */
export const DEFAULT_TRIAGE_CONFIG: TriageConfig = {
	enabled: false,
	observeOnly: false,
	minCategorySurface: 1,
};

/**
 * Read the gate config from env. `SHOR_TRIAGE_GATE`:
 *   - unset / `0` / `off`  → disabled (identity no-op, matches stock behavior).
 *   - `1` / `on`           → active (real skip decisions).
 *   - `observe` / `2`      → active but observe-only (compute + log, never skip).
 * `SHOR_TRIAGE_MIN_SURFACE` overrides the per-category surface floor (default 1).
 */
export function triageConfigFromEnv(): TriageConfig {
	const raw = (process.env.SHOR_TRIAGE_GATE ?? "").trim().toLowerCase();
	const enabled = raw === "1" || raw === "on" || raw === "observe" || raw === "2";
	const observeOnly = raw === "observe" || raw === "2";
	const minParsed = Number.parseInt(process.env.SHOR_TRIAGE_MIN_SURFACE ?? "", 10);
	const minCategorySurface = Number.isFinite(minParsed) && minParsed >= 0
		? minParsed
		: DEFAULT_TRIAGE_CONFIG.minCategorySurface;
	return { enabled, observeOnly, minCategorySurface };
}

/** Force a would-be `skip` back to `scan` under observe-only, preserving the reason. */
function applyObserveOnly(v: TriageVerdict, cfg: TriageConfig): TriageVerdict {
	if (v.decision === "skip" && cfg.observeOnly) {
		return { ...v, decision: "scan", wouldSkip: true, reason: `observe-only: ${v.reason}` };
	}
	return v;
}

/**
 * Decide whether to scan a target origin. Skips ONLY a target that a cheap probe
 * determined to be unreachable; every other state (reachable, or reachability never
 * determined) scans. Pure.
 */
export function gateTarget(signal: TargetSignal, cfg: TriageConfig): TriageVerdict {
	const base: TriageVerdict = { kind: "target", subject: signal.target, decision: "scan", reason: "" };
	if (!signal.reachabilityDetermined) {
		return applyObserveOnly({ ...base, reason: "reachability not determined; bias to scan" }, cfg);
	}
	if (signal.reachable) {
		return applyObserveOnly({ ...base, reason: "target responded to cheap probe" }, cfg);
	}
	return applyObserveOnly(
		{ ...base, decision: "skip", reason: "target origin did not respond to a cheap reachability probe" },
		cfg,
	);
}

/**
 * Decide whether to run a category's exploitation pass. Skips ONLY a category recon
 * actually probed and found strictly fewer than `minCategorySurface` surface hits; an
 * un-probed category always scans (unknown ⇒ bias to scan). Pure.
 */
export function gateCategory(signal: CategorySignal, cfg: TriageConfig): TriageVerdict {
	const base: TriageVerdict = { kind: "category", subject: signal.category, decision: "scan", reason: "" };
	if (!signal.probed) {
		return applyObserveOnly({ ...base, reason: "category surface not probed; bias to scan" }, cfg);
	}
	if (signal.surfaceHits >= cfg.minCategorySurface) {
		return applyObserveOnly(
			{ ...base, reason: `recon found ${signal.surfaceHits} surface hit(s) (>= ${cfg.minCategorySurface})` },
			cfg,
		);
	}
	return applyObserveOnly(
		{
			...base,
			decision: "skip",
			reason: `recon probed and found no ${signal.category} surface (hits=${signal.surfaceHits} < min=${cfg.minCategorySurface})`,
		},
		cfg,
	);
}

/**
 * Case-insensitive substring markers of each category's attack surface. Coarse ON
 * PURPOSE: a hit only counts surface as PRESENT (⇒ scan), never as absent — absence
 * needs `probed=true` from the caller. Kept small so a normal recon blob does not
 * falsely zero-out a category.
 */
const CATEGORY_SURFACE_MARKERS: Record<FindingCategory, readonly string[]> = {
	injection: ["sql", "query", "db", "param", "search", "?id=", "orderby", "filter"],
	xss: ["html", "render", "innerhtml", "reflect", "template", "comment", "message", "<script"],
	auth: ["login", "token", "jwt", "session", "password", "oauth", "oidc", "signin"],
	authz: ["role", "admin", "permission", "acl", "owner", "tenant", "/users/", "idor"],
	ssrf: ["url=", "fetch", "webhook", "proxy", "redirect", "callback", "image_url", "avatar"],
	logic: ["workflow", "price", "quantity", "coupon", "cart", "checkout", "state", "step"],
	"misconfig-web": ["header", "cors", "cookie", "csp", "tls", "x-powered-by", "config", "debug"],
};

/**
 * Coarse deriver: turn a recon evidence blob (report text, endpoint list, etc.) into
 * per-category {@link CategorySignal}s by counting distinct surface markers present.
 * `probed` is the CALLER's assertion that recon genuinely ran for that category —
 * default `true` here, but pass `probed=false` for any category recon never covered so
 * the gate keeps biasing to scan rather than skipping on a coarse zero.
 */
export function deriveCategorySignals(
	reconText: string,
	categories: readonly FindingCategory[],
	probed = true,
): CategorySignal[] {
	const hay = reconText.toLowerCase();
	return categories.map((category) => {
		const markers = CATEGORY_SURFACE_MARKERS[category] ?? [];
		const surfaceHits = markers.reduce((n, m) => (hay.includes(m) ? n + 1 : n), 0);
		return { category, probed, surfaceHits };
	});
}
