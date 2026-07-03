// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Joern CPG driver (spec T10, F14, R7) — Apache-2.0 Joern ONLY, never CodeQL.
 *
 * Orchestrates the deterministic pipeline: resolve the Joern binaries, build a
 * Code Property Graph for the cloned repo (`joern-parse`), run a spec-generated
 * `reachableByFlows` script (`joern --script`), then parse the JSON it emits into
 * typed observations. The LLM only supplies specs (via `specs/infer`); the driver
 * itself is deterministic over Joern's output.
 *
 * FAIL-OPEN + FLAG-GATED: the whole thing is default-OFF (`SHOR_TAINT`), and any
 * missing binary / build error / query error returns a `degraded` result with an
 * empty observation set instead of throwing — a stock scan with no taint flag,
 * or an image without Joern, behaves exactly as today.
 */

import { execFile } from "node:child_process";
import { constants as fsConstants, promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ActivityLogger } from "../../../types/activity-logger.js";
import { inferSpec } from "../specs/infer.js";
import type { TaintDegradation, TaintLanguage, TaintResult } from "../types.js";
import { parseObservations } from "./parse.js";
import { buildTaintScript, joernLanguageFlag, SCRIPT_PARAMS } from "./queries.js";

const execFileP = promisify(execFile);

const NOOP_LOGGER: ActivityLogger = { info: () => {}, warn: () => {}, error: () => {} };

/** CPG build can be slow on a large repo; the query script is comparatively fast. */
const BUILD_TIMEOUT_MS = 12 * 60_000;
const QUERY_TIMEOUT_MS = 8 * 60_000;

/** Resolved Joern executables. */
interface JoernBins {
	readonly joern: string;
	readonly joernParse: string;
}

/** Master flag: taint stays OFF unless explicitly enabled. */
export function taintEnabled(): boolean {
	return process.env.SHOR_TAINT === "1";
}

/** Does `name` resolve to an executable on PATH? (mirrors preflight/tooling-discovery) */
async function isOnPath(name: string, pathEnv: string): Promise<boolean> {
	for (const dir of pathEnv.split(path.delimiter).filter(Boolean)) {
		try {
			await fs.access(path.join(dir, name), fsConstants.X_OK);
			return true;
		} catch {
			// keep scanning
		}
	}
	return false;
}

/**
 * Resolve the `joern` + `joern-parse` binaries. Prefers an explicit
 * `SHOR_JOERN_DIR` install (expects `<dir>/joern` + `<dir>/joern-parse`), then
 * falls back to PATH. Returns null when either binary is missing.
 */
export async function resolveJoernBins(
	env: NodeJS.ProcessEnv = process.env,
): Promise<JoernBins | null> {
	const dir = env.SHOR_JOERN_DIR?.trim();
	if (dir) {
		const joern = path.join(dir, "joern");
		const joernParse = path.join(dir, "joern-parse");
		try {
			await fs.access(joern);
			await fs.access(joernParse);
			return { joern, joernParse };
		} catch {
			// fall through to PATH
		}
	}
	const pathEnv = env.PATH ?? "";
	if ((await isOnPath("joern", pathEnv)) && (await isOnPath("joern-parse", pathEnv))) {
		return { joern: "joern", joernParse: "joern-parse" };
	}
	return null;
}

/** Build the CPG. Returns true on success; logs + returns false on failure. */
async function buildCpg(
	bins: JoernBins,
	repoPath: string,
	cpgPath: string,
	language: TaintLanguage,
	logger: ActivityLogger,
): Promise<boolean> {
	const args = [repoPath, "--output", cpgPath];
	const flag = joernLanguageFlag(language);
	if (flag) args.push("--language", flag);
	try {
		await execFileP(bins.joernParse, args, {
			timeout: BUILD_TIMEOUT_MS,
			maxBuffer: 1 << 26,
		});
		return true;
	} catch (e) {
		logger.warn("taint: joern-parse failed (continuing without taint)", {
			error: e instanceof Error ? e.message : String(e),
			language,
			flag,
		});
		return false;
	}
}

/** Run the generated query script against the CPG. Returns the out-file path or null. */
async function runScript(
	bins: JoernBins,
	scriptPath: string,
	cpgPath: string,
	outPath: string,
	logger: ActivityLogger,
): Promise<boolean> {
	try {
		await execFileP(
			bins.joern,
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
		logger.warn("taint: joern --script failed (continuing without taint)", {
			error: e instanceof Error ? e.message : String(e),
		});
		return false;
	}
}

export interface RunTaintOptions {
	/** Force a language instead of detecting from the repo. */
	language?: TaintLanguage;
	/** Working dir for the CPG + script + output (defaults to an os.tmpdir mkdtemp). */
	workDir?: string;
	logger?: ActivityLogger;
}

function degraded(
	reason: TaintDegradation["reason"],
	detail: string,
	language: TaintLanguage,
	specInferredBy: "default" | "llm",
): TaintResult {
	return { observations: [], language, specInferredBy, degraded: { reason, detail } };
}

/**
 * Run the full taint analysis over a cloned repo. Never throws: every failure
 * path returns a `degraded` result with an empty observation set. When disabled
 * or Joern is absent the call is effectively a no-op.
 */
export async function runTaintAnalysis(
	repoPath: string,
	opts: RunTaintOptions = {},
): Promise<TaintResult> {
	const logger = opts.logger ?? NOOP_LOGGER;

	if (!taintEnabled()) {
		return degraded("disabled", "SHOR_TAINT!=1", "unknown", "default");
	}

	const bins = await resolveJoernBins();
	if (!bins) {
		return degraded(
			"joern_missing",
			"joern/joern-parse not found on PATH or SHOR_JOERN_DIR",
			"unknown",
			"default",
		);
	}

	const { spec, language } = await inferSpec(repoPath, {
		logger,
		...(opts.language ? { language: opts.language } : {}),
	});

	const workDir =
		opts.workDir ?? (await fs.mkdtemp(path.join(os.tmpdir(), "shor-taint-")));
	const cpgPath = path.join(workDir, "cpg.bin");
	const scriptPath = path.join(workDir, "taint-query.sc");
	const outPath = path.join(workDir, "flows.json");

	if (!(await buildCpg(bins, repoPath, cpgPath, language, logger))) {
		return degraded("cpg_build_failed", "joern-parse non-zero exit", language, spec.inferredBy);
	}

	await fs.writeFile(scriptPath, buildTaintScript(spec), "utf8");

	if (!(await runScript(bins, scriptPath, cpgPath, outPath, logger))) {
		return degraded("query_failed", "joern --script non-zero exit", language, spec.inferredBy);
	}

	let observations: TaintResult["observations"] = [];
	try {
		const raw = JSON.parse(await fs.readFile(outPath, "utf8"));
		observations = parseObservations(raw);
	} catch (e) {
		return degraded(
			"query_failed",
			`unreadable flows.json: ${e instanceof Error ? e.message : String(e)}`,
			language,
			spec.inferredBy,
		);
	}

	logger.info("taint: analysis complete", {
		language,
		specInferredBy: spec.inferredBy,
		observations: observations.length,
		direct: observations.filter((o) => o.flowKind === "direct").length,
		secondOrder: observations.filter((o) => o.flowKind === "second_order").length,
	});

	return { observations, language, specInferredBy: spec.inferredBy, cpgPath };
}
