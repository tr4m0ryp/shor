// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Guard-dominance driver (spec T10, F9b, R7).
 *
 * Runs the dominator query against the CPG task 015 ALREADY built (`cpg.bin`),
 * reusing its binaries — we never re-parse the repo. Pipeline: write the generated
 * script, run `joern --script` against the existing CPG, parse the JSON into
 * candidates, then fold in the LLM semantic layer.
 *
 * FAIL-OPEN + FLAG-GATED (`SHOR_GUARD_DOMINANCE`, default OFF): a missing flag,
 * absent CPG, missing Joern, or a query error returns a `degraded` result with an
 * empty finding set — a stock scan is unchanged.
 */

import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { resolveJoernBins } from "../joern/driver.js";
import { SCRIPT_PARAMS } from "../joern/queries.js";
import {
	buildGuardDominanceScript,
	type GuardQueryMatchers,
	parseGuardResults,
} from "./query.js";
import { validateGuards } from "./semantic.js";
import type {
	GuardDominanceDegradation,
	GuardDominanceResult,
	GuardRawResult,
} from "./types.js";

const execFileP = promisify(execFile);
const NOOP_LOGGER: ActivityLogger = { info: () => {}, warn: () => {}, error: () => {} };

/** The dominator query is comparatively cheap once the CPG exists. */
const QUERY_TIMEOUT_MS = 8 * 60_000;

/** Master flag: guard-dominance stays OFF unless explicitly enabled. */
export function guardDominanceEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
	return env.SHOR_GUARD_DOMINANCE === "1";
}

/** A fake-injectable query runner (tests supply flows without a Joern install). */
export type GuardQueryRunner = (
	scriptPath: string,
	cpgPath: string,
	outPath: string,
) => Promise<boolean>;

export interface RunGuardDominanceOptions {
	/** Repo dir for the LLM semantic layer (skipped when absent). */
	sourceDir?: string;
	/** Guard/sink matcher overrides. */
	matchers?: GuardQueryMatchers;
	/** Working dir for the script + output (defaults to an os.tmpdir mkdtemp). */
	workDir?: string;
	logger?: ActivityLogger;
	/** Inject the Joern run (tests); defaults to the real `joern --script` call. */
	runQuery?: GuardQueryRunner;
	/** Force-enable/disable the semantic layer (forwarded to {@link validateGuards}). */
	semanticEnabled?: boolean;
}

function degraded(
	reason: GuardDominanceDegradation["reason"],
	detail: string,
): GuardDominanceResult {
	return { findings: [], degraded: { reason, detail } };
}

/** The default runner: `joern --script` against the existing CPG. */
function defaultRunner(joern: string, logger: ActivityLogger): GuardQueryRunner {
	return async (scriptPath, cpgPath, outPath) => {
		try {
			await execFileP(
				joern,
				[
					"--script",
					scriptPath,
					"--param",
					`${SCRIPT_PARAMS.cpg}=${cpgPath}`,
					"--param",
					`${SCRIPT_PARAMS.out}=${outPath}`,
				],
				{ timeout: QUERY_TIMEOUT_MS, maxBuffer: 1 << 26 },
			);
			return true;
		} catch (e) {
			logger.warn("guard-dominance: joern --script failed (continuing without it)", {
				error: e instanceof Error ? e.message : String(e),
			});
			return false;
		}
	};
}

/**
 * Run the guard-dominance pass against an EXISTING CPG. `cpgPath` is the
 * `TaintResult.cpgPath` from task 015 — reused, never rebuilt. Never throws;
 * every failure path returns a `degraded` result with an empty finding set.
 */
export async function runGuardDominance(
	cpgPath: string | undefined,
	opts: RunGuardDominanceOptions = {},
): Promise<GuardDominanceResult> {
	const logger = opts.logger ?? NOOP_LOGGER;

	if (!guardDominanceEnabled()) {
		return degraded("disabled", "SHOR_GUARD_DOMINANCE!=1");
	}
	if (!cpgPath) {
		return degraded("no_cpg", "no CPG path from the taint driver (015); nothing to query");
	}

	let runQuery = opts.runQuery;
	if (!runQuery) {
		const bins = await resolveJoernBins();
		if (!bins) {
			return degraded("joern_missing", "joern not found on PATH or SHOR_JOERN_DIR");
		}
		runQuery = defaultRunner(bins.joern, logger);
	}

	const workDir =
		opts.workDir ?? (await fs.mkdtemp(path.join(os.tmpdir(), "shor-guard-")));
	const scriptPath = path.join(workDir, "guard-dominance.sc");
	const outPath = path.join(workDir, "guards.json");

	await fs.writeFile(scriptPath, buildGuardDominanceScript(opts.matchers), "utf8");
	if (!(await runQuery(scriptPath, cpgPath, outPath))) {
		return degraded("query_failed", "joern --script non-zero exit");
	}

	let raw: GuardRawResult;
	try {
		raw = JSON.parse(await fs.readFile(outPath, "utf8")) as GuardRawResult;
	} catch (e) {
		return degraded("query_failed", `unreadable guards.json: ${e instanceof Error ? e.message : String(e)}`);
	}

	const candidates = parseGuardResults(raw);
	const findings = await validateGuards(candidates, {
		...(opts.sourceDir !== undefined && { sourceDir: opts.sourceDir }),
		...(opts.semanticEnabled !== undefined && { enabled: opts.semanticEnabled }),
		logger,
	});

	logger.info("guard-dominance: analysis complete", {
		candidates: candidates.length,
		missingGuard: findings.filter((f) => f.disposition === "missing_guard").length,
		wrongGuard: findings.filter((f) => f.disposition === "wrong_guard").length,
	});
	return { findings };
}
