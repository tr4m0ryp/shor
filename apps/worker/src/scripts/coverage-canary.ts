#!/usr/bin/env tsx

// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Local coverage canary (OPTIONAL live harness — NOT part of `vitest run`).
 *
 * Runs the real in-process pipeline (`runScanPipeline`) against the bundled
 * `.acceptance/avelero` fixture and proves the breadth fix end-to-end:
 *   - recon exercised at least its coverage floor of distinct tools, and
 *   - every exploit agent that actually ran fired >= 1 of its category tools.
 *
 * It is deliberately a standalone `tsx` script (NOT `*.test.ts`) so the CI unit
 * suite (`coverage/canary.test.ts`) never reaches the network. The fixture
 * `.env` (DeepSeek key, target URL, repo path, ROE) is gitignored, so when it
 * is absent this harness prints a single BLOCKED line and exits 0 (non-failing)
 * — a BLOCKED run is NEVER reported as PASS.
 *
 * Run:  pnpm exec tsx apps/worker/src/scripts/coverage-canary.ts
 */

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";
import { ConsoleActivityLogger } from "../job/logger.js";
import { skillTracker } from "../job/progress/skill-tracker.js";
import { policyFor } from "../services/coverage/evaluate.js";
import type { AgentName } from "../types/agents.js";

/** Distinct exit codes so a caller can tell BLOCKED apart from PASS/FAIL. */
const EXIT_PASS = 0;
const EXIT_BLOCKED = 0; // non-failing: absent fixture is not a regression
const EXIT_FAIL = 1;

/** Repo root holding `.acceptance/` (scripts/ -> src/ -> worker/ -> apps/ -> root). */
function repoRoot(): string {
	const here = dirname(fileURLToPath(import.meta.url));
	return resolve(here, "..", "..", "..", "..");
}

/** One reached exploit agent must fire >= 1 tool from its category pool. */
const EXPLOIT_AGENTS: readonly AgentName[] = [
	"injection-exploit",
	"xss-exploit",
	"auth-exploit",
	"ssrf-exploit",
	"authz-exploit",
];

/** True when SOME credential the engine accepts is present in the environment. */
function hasProviderKey(): boolean {
	return Boolean(
		process.env.DEEPSEEK_API_KEY?.trim() ||
			process.env.ANTHROPIC_API_KEY?.trim() ||
			process.env.ANTHROPIC_AUTH_TOKEN?.trim(),
	);
}

/** Print the canonical BLOCKED line and exit non-failing. Never a PASS. */
function blocked(reason: string): never {
	console.log(`BLOCKED: fixture env/key absent (${reason})`);
	process.exit(EXIT_BLOCKED);
}

/**
 * Load `.acceptance/avelero/.env` and confirm the run is viable. Returns the
 * resolved scan params, or short-circuits via `blocked()` when the fixture or
 * its credentials are missing.
 */
function loadFixtureOrBlock(): {
	scanId: string;
	targetUrl: string;
	repoPath: string;
} {
	const envPath = resolve(repoRoot(), ".acceptance", "avelero", ".env");
	if (!existsSync(envPath)) blocked(`no ${envPath}`);
	dotenv.config({ path: envPath });

	if (!hasProviderKey()) blocked("no DEEPSEEK_API_KEY / ANTHROPIC_API_KEY");

	const targetUrl = process.env.SHOR_TARGET_URL?.trim();
	if (!targetUrl) blocked("no SHOR_TARGET_URL");

	const repoPath = process.env.SHOR_REPO_PATH?.trim();
	if (!repoPath) blocked("no SHOR_REPO_PATH");
	if (!existsSync(repoPath)) blocked(`SHOR_REPO_PATH missing: ${repoPath}`);

	const scanId = process.env.SHOR_SCAN_ID?.trim() || `canary-${Date.now()}`;
	return { scanId, targetUrl, repoPath };
}

/** A single coverage assertion outcome, for the end-of-run report. */
interface Check {
	readonly label: string;
	readonly ok: boolean;
	readonly detail: string;
}

/**
 * Build the coverage assertions from the post-run `skillTracker` snapshot.
 * recon MUST reach its floor; each exploit agent that ran MUST have fired >= 1
 * category tool. Exploit agents that never ran are not asserted (an upstream
 * vuln phase may have found nothing to exploit — not a coverage regression).
 */
function checkCoverage(used: Record<string, string[]>): Check[] {
	const checks: Check[] = [];

	const reconPolicy = policyFor("recon");
	const reconRan = (used.recon ?? []).filter((t) =>
		reconPolicy?.candidates.includes(t),
	);
	const floor = reconPolicy?.minCount ?? 0;
	checks.push({
		label: "recon reached its breadth floor",
		ok: reconRan.length >= floor,
		detail: `ran ${reconRan.length}/${floor} candidate tools [${reconRan.join(", ") || "none"}]`,
	});

	for (const agent of EXPLOIT_AGENTS) {
		const ran = used[agent];
		if (!ran || ran.length === 0) continue; // agent never reached; skip
		const policy = policyFor(agent);
		const onPolicy = ran.filter((t) => policy?.candidates.includes(t));
		checks.push({
			label: `${agent} fired a category tool`,
			ok: onPolicy.length >= 1,
			detail: `ran [${ran.join(", ")}] (on-policy: ${onPolicy.join(", ") || "none"})`,
		});
	}

	return checks;
}

async function main(): Promise<void> {
	const params = loadFixtureOrBlock();
	const logger = new ConsoleActivityLogger();

	logger.info("coverage-canary: running live pipeline against fixture", {
		scanId: params.scanId,
		targetUrl: params.targetUrl,
	});

	// Dynamic import so a typecheck / `--help` never forces the heavy pipeline
	// graph (container, SDK, audit) to load before the fixture gate has run.
	const { runScanPipeline } = await import("../job/pipeline.js");
	await runScanPipeline(params, logger);

	const used = skillTracker.all();
	const checks = checkCoverage(used);

	console.log("\n=== coverage-canary results ===");
	for (const c of checks) {
		console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.label} — ${c.detail}`);
	}

	const failed = checks.filter((c) => !c.ok);
	if (failed.length > 0) {
		console.log(`\nFAIL: ${failed.length} coverage assertion(s) failed`);
		process.exit(EXIT_FAIL);
	}
	console.log(`\nPASS: all ${checks.length} coverage assertion(s) held`);
	process.exit(EXIT_PASS);
}

main().catch((err: unknown) => {
	// A crash is a genuine failure (not BLOCKED): surface it as non-zero.
	console.error(
		`coverage-canary errored: ${err instanceof Error ? err.stack ?? err.message : String(err)}`,
	);
	process.exit(EXIT_FAIL);
});
