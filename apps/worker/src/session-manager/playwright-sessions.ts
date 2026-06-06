// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { PlaywrightSession } from "../types/index.js";

/**
 * Playwright session mapping — assigns each agent prompt to a browser session for
 * isolation. Keys are `promptTemplate` values from the AGENTS registry.
 *
 * This map MUST be EXHAUSTIVE over every registered agent. `loadPrompt` now FAILS
 * FAST (throws) for any prompt not declared here instead of silently falling back
 * to a shared session — that poor fallback once let threat-model, the screen
 * voters, and logic/misconfig-web collide on `agent1`. Browserless agents
 * (threat-model, screen voters) are still declared explicitly; their session is
 * simply unused. A unit test asserts every registered agent appears here, so a
 * new agent without a declaration fails CI rather than degrading at runtime.
 */
export const PLAYWRIGHT_SESSION_MAPPING: Record<string, PlaywrightSession> =
	Object.freeze({
		// Phase 1: Pre-reconnaissance
		"pre-recon-code": "agent1",

		// Phase 2: Reconnaissance
		recon: "agent2",

		// Phase 2b: Threat model (synthesis; browserless — session declared, unused).
		"threat-model": "agent1",

		// Phase 3: Vulnerability Analysis (7 parallel agents — one DISTINCT browser
		// session each so a full-width group never shares a profile. logic +
		// misconfig-web were unmapped and fell back to agent1, colliding with
		// injection under parallelism; agent6/agent7 give them their own.)
		"vuln-injection": "agent1",
		"vuln-xss": "agent2",
		"vuln-auth": "agent3",
		"vuln-ssrf": "agent4",
		"vuln-authz": "agent5",
		"vuln-logic": "agent6",
		"vuln-misconfig-web": "agent7",

		// Phase 4: Exploitation (7 parallel agents — same per-category session as the
		// vuln counterpart so the established browser/auth state is reused).
		"exploit-injection": "agent1",
		"exploit-xss": "agent2",
		"exploit-auth": "agent3",
		"exploit-ssrf": "agent4",
		"exploit-authz": "agent5",
		"exploit-logic": "agent6",
		"exploit-misconfig-web": "agent7",

		// Phase 3b: Adversarial screen panel (lens-voters; browserless — sessions
		// declared per-category, unused, so no screen agent silently falls back).
		"screen-injection": "agent1",
		"screen-xss": "agent2",
		"screen-auth": "agent3",
		"screen-ssrf": "agent4",
		"screen-authz": "agent5",
		"screen-logic": "agent6",
		"screen-misconfig-web": "agent7",

		// Phase 4b: Exploit retry pass (same session assignments; runs sequentially
		// after the primary pass so there is no browser contention)
		"exploit-injection-retry": "agent1",
		"exploit-xss-retry": "agent2",
		"exploit-auth-retry": "agent3",
		"exploit-ssrf-retry": "agent4",
		"exploit-authz-retry": "agent5",

		// Phase 5: Reporting
		"report-executive": "agent3",

		// Phase 6: Attack-Surface Synthesis
		"attack-surface": "agent3",
	});

/**
 * Identity-scoped Playwright session label (task 008). A template-literal type
 * disjoint from {@link PlaywrightSession} (`agent1`..`agent5`): an identity
 * session is NEVER one of the phase sessions, so an authz agent acting as
 * identity A vs B cannot collide with — or bleed cookies into — a phase browser.
 */
export type IdentitySessionLabel = `identity-${string}`;

/**
 * Slugify an identity label into a deterministic, credential-free, filesystem-
 * safe token: lowercase, every run of non-alphanumerics collapses to a single
 * hyphen, leading/trailing hyphens trimmed. Degenerate input (empty / all
 * punctuation) falls back to a stable token so a label never yields "".
 */
export function identitySlug(label: string): string {
	const slug = label
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
	return slug.length > 0 ? slug : "identity";
}

/**
 * Deterministic, credential-free Playwright session label for an identity —
 * `identity-<slug>`. Namespaced away from the `agent1`..`agent5` phase sessions
 * so each identity keeps its cookies in its own browser profile (no cross-
 * identity bleed). Built from the label ONLY — never from any credential.
 */
export function identitySessionLabel(label: string): IdentitySessionLabel {
	return `identity-${identitySlug(label)}`;
}
