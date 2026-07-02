// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Render-coverage guard (task 005 / spec T4) — the safety net for the whole
 * auth-coherence change. Renders EVERY agent prompt in the vulnerability, screen,
 * and exploitation lanes through the production entry point `loadPrompt` and
 * proves, per prompt:
 *   1. the recursive @include resolver expanded every directive (none survived);
 *   2. no RESOLVABLE `{{...}}` placeholder survived — checked as the CLOSED SET
 *      the interpolation pipeline owns, NOT a blanket `{{...}}` scan, because the
 *      xss / injection lanes legitimately TEACH `{{7*7}}`-style SSTI and
 *      client-side-template payloads as literal sink examples (same rationale the
 *      sibling screen-fp-rules.test.ts records);
 *   3. the canonical auth-scaffolding block reached the agent — the assertion
 *      that catches the original coverage gap;
 *   4. the two provisioned identity labels landed in that block (proving the
 *      block's `{{IDENTITIES}}` slot resolved).
 *
 * Prompts are DISCOVERED by reading the lane directories, so a newly added prompt
 * is auto-covered, and a prompt that ships WITHOUT the block fails loudly, naming
 * itself. Rendered with a sample authenticated-scan config + a two-identity
 * PromptContext.
 */

import { readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PROMPTS_DIR } from "../../paths.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { DistributedConfig } from "../../types/config.js";
import { loadPrompt } from "./loader.js";
import type { PromptContext } from "./prompt-context.js";

// The three per-scan AGENT lanes. recon / attack-surface / reporting / finalize
// are not vuln-hunting agents; the spec scopes this guard to the lanes that MUST
// carry the subject-vs-mechanism auth framing.
const AGENT_LANES = ["vulnerability", "screen", "exploitation"] as const;

// Stable distinctive marker: the opening tag of the canonical block in
// shared/_auth-scaffolding.txt. Present iff the block was wired in AND expanded.
const AUTH_SCAFFOLDING_MARKER = "<auth_scaffolding>";

// Two provisioned identities. The labels are distinctive sentinels so assertion
// (4) can prove `{{IDENTITIES}}` resolved into the auth-scaffolding block.
const IDENTITY_OWNER = "shor-guard-owner";
const IDENTITY_MEMBER = "shor-guard-member";
const IDENTITIES = `- ${IDENTITY_OWNER} (role: owner)\n- ${IDENTITY_MEMBER} (role: member)`;

const VARS = { webUrl: "https://target.example", repoPath: "/tmp/repo" };

// A representative authenticated-scan config: credentials + MFA + avoid/focus
// rules so `{{AUTH_CONTEXT}}` and `{{RULES_AVOID}}` render real values. login_flow
// is intentionally omitted so `{{LOGIN_INSTRUCTIONS}}` -> "" — the login
// instructions seam (and its deliberate out-of-band `{{SHOR_LOGIN_*}}` tokens) has
// its own tests; pulling it in here would only add documented-but-noisy survivors
// to assertion 2 without widening auth-framing coverage.
const SAMPLE_CONFIG: DistributedConfig = {
	avoid: [{ description: "Do not touch /billing", type: "path", url_path: "/billing" }],
	focus: [{ description: "Prioritise the JSON API", type: "path", url_path: "/api" }],
	authentication: {
		login_type: "form",
		login_url: "https://target.example/login",
		credentials: {
			username: "scaffold-user",
			password: "resolved-out-of-band",
			totp_secret: "resolved-out-of-band",
		},
		success_condition: { type: "url_contains", value: "/dashboard" },
	},
	description: "render-coverage guard sample target",
};

// A populated context so every PromptContext-backed slot resolves to a real value
// rather than the "(none)" sentinel — the strictest form of assertion 2.
const CONTEXT: PromptContext = {
	identities: IDENTITIES,
	threatModel: "T-1: tenant isolation; T-2: privilege boundaries",
	historicalSeed: "prior round flagged an IDOR on /api/orders",
	fpRules: "self-XSS in the admin debug console is accepted risk",
};

const noopLogger: ActivityLogger = {
	info: () => {},
	warn: () => {},
	error: () => {},
};

// The CLOSED SET of `{{...}}` placeholders the build pipeline is responsible for
// resolving — mirrors exactly the two resolvers: interpolateVariables
// (interpolation.ts) and applyPromptContext (prompt-context.ts). Assertion 2
// proves NONE of these survives a render. Deliberately NOT a blanket `{{...}}`
// regex: the xss / injection prompts embed literal SSTI payloads ({{7*7}},
// {{constructor.constructor(...)}}, {{config.items()}}, {{var|safe}}, ...) as sink
// documentation; those are not interpolation slots and must be left untouched.
const RESOLVABLE_PLACEHOLDERS = [
	// interpolateVariables — variables + config-derived.
	"{{WEB_URL}}",
	"{{REPO_PATH}}",
	"{{PLAYWRIGHT_SESSION}}",
	"{{AUTH_CONTEXT}}",
	"{{DESCRIPTION}}",
	"{{RULES_AVOID}}",
	"{{RULES_FOCUS}}",
	"{{LOGIN_INSTRUCTIONS}}",
	// applyPromptContext — per-round PromptContext slots.
	"{{THREAT_MODEL}}",
	"{{HISTORICAL_SEED}}",
	"{{PARTITION}}",
	"{{LENS}}",
	"{{VOTER_INDEX}}",
	"{{IDENTITIES}}",
	"{{FP_RULES}}",
] as const;

/** Discover a lane's prompts by basename (sans .txt) so new prompts auto-enrol. */
function discoverPrompts(lane: string): string[] {
	return readdirSync(join(PROMPTS_DIR, lane))
		.filter((file) => file.endsWith(".txt"))
		.map((file) => file.slice(0, -".txt".length))
		.sort();
}

// Memoise one render per prompt, shared across its four assertions.
const renderCache = new Map<string, Promise<string>>();
function render(promptName: string): Promise<string> {
	let pending = renderCache.get(promptName);
	if (pending === undefined) {
		pending = loadPrompt(
			promptName,
			VARS,
			SAMPLE_CONFIG,
			noopLogger,
			PROMPTS_DIR,
			CONTEXT,
		);
		renderCache.set(promptName, pending);
	}
	return pending;
}

describe("auth render-coverage guard (T4)", () => {
	for (const lane of AGENT_LANES) {
		const prompts = discoverPrompts(lane);

		// Guard discovery itself: a wrong path / empty lane must FAIL loudly rather
		// than vacuously pass zero prompts.
		it(`${lane}: discovers at least one prompt to cover`, () => {
			expect(prompts.length).toBeGreaterThan(0);
		});

		for (const name of prompts) {
			describe(`${lane}/${name}`, () => {
				it("expands every @include (recursive resolver left no directive)", async () => {
					const rendered = await render(name);
					expect(
						rendered,
						`unexpanded @include survived in ${lane}/${name}`,
					).not.toContain("@include(");
				});

				it("resolves every pipeline placeholder (SSTI payload literals aside)", async () => {
					const rendered = await render(name);
					const survivors = RESOLVABLE_PLACEHOLDERS.filter((token) =>
						rendered.includes(token),
					);
					expect(
						survivors,
						`unresolved pipeline placeholders in ${lane}/${name}`,
					).toEqual([]);
				});

				it("carries the canonical auth-scaffolding block", async () => {
					const rendered = await render(name);
					expect(
						rendered.includes(AUTH_SCAFFOLDING_MARKER),
						`auth-scaffolding block missing from ${lane}/${name}`,
					).toBe(true);
				});

				it("resolves {{IDENTITIES}} — both provisioned labels present", async () => {
					const rendered = await render(name);
					expect(
						rendered,
						`owner identity label missing from ${lane}/${name}`,
					).toContain(IDENTITY_OWNER);
					expect(
						rendered,
						`member identity label missing from ${lane}/${name}`,
					).toContain(IDENTITY_MEMBER);
				});
			});
		}
	}
});
