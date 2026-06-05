// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Scan-level prompt-context assembler.
 *
 * Reads the per-scan artifacts that frame downstream agents — the threat model
 * and (when present) the historical signal, identity set, and org false-positive
 * rules — and returns a populated {@link PromptContext}. EVERY source is
 * OPTIONAL: a missing/unreadable/empty artifact simply leaves its field unset,
 * which `applyPromptContext` renders as the neutral "(none)" sentinel.
 *
 * NEVER reads or emits credentials. The identity renderer is allowlist-driven
 * (labels/roles only) and the config argument's `authentication.credentials` is
 * deliberately untouched (ADR-050 / auth-context.ts rule).
 */

import { fs, path } from "zx";
import type { DistributedConfig } from "../../types/config.js";
import type { PromptContext } from "../prompt-manager/prompt-context.js";
import { renderHistoricalSeed, renderIdentities } from "./artifacts.js";
import { renderThreatModel } from "./render.js";
import { parseThreatModel } from "./schema.js";

/** Threat model emitted by the threat-model agent (task 005). */
export const THREAT_MODEL_FILE = "threat_model.json";
/** Prior-exploit hot-spots, produced by task 006. */
export const HISTORICAL_SIGNAL_FILE = "historical_signal.json";
/** Identity labels/roles metadata (NEVER credentials), produced by task 008. */
export const SCAN_IDENTITIES_FILE = "scan_identities.json";
/** Env var carrying org false-positive precedents (task 016). */
export const FP_RULES_ENV = "SHOR_FP_RULES";

/** Read + JSON-parse a deliverable; `undefined` when absent or unparseable. */
async function readJsonFile(
	deliverablesPath: string,
	filename: string,
): Promise<unknown> {
	const file = path.join(deliverablesPath, filename);
	if (!(await fs.pathExists(file))) return undefined;
	try {
		return JSON.parse(await fs.readFile(file, "utf8"));
	} catch {
		return undefined;
	}
}

/**
 * Build the per-scan {@link PromptContext} from the deliverables directory, the
 * (optional) scan config, and the environment. Wired into the per-agent prompt
 * build so every downstream agent's `{{THREAT_MODEL}}` (and the sibling vars)
 * resolves to a real value once the producing artifacts exist; before then they
 * fall back to "(none)".
 *
 * `_config` is accepted for call-site symmetry and as a forward seam; it is NOT
 * read today (nothing in `DistributedConfig` feeds these fields, and its
 * credential block is off-limits).
 */
export async function assembleScanPromptContext(
	deliverablesPath: string,
	_config?: DistributedConfig | null,
	env?: NodeJS.ProcessEnv,
): Promise<PromptContext> {
	const environment = env ?? process.env;
	const context: PromptContext = {};

	const threatModelRaw = await readJsonFile(deliverablesPath, THREAT_MODEL_FILE);
	if (threatModelRaw !== undefined) {
		const model = parseThreatModel(threatModelRaw);
		if (model !== null) context.threatModel = renderThreatModel(model);
	}

	const historicalRaw = await readJsonFile(
		deliverablesPath,
		HISTORICAL_SIGNAL_FILE,
	);
	if (historicalRaw !== undefined) {
		const seed = renderHistoricalSeed(historicalRaw);
		if (seed !== null) context.historicalSeed = seed;
	}

	const identitiesRaw = await readJsonFile(
		deliverablesPath,
		SCAN_IDENTITIES_FILE,
	);
	if (identitiesRaw !== undefined) {
		const identities = renderIdentities(identitiesRaw);
		if (identities !== null) context.identities = identities;
	}

	const fpRules = environment[FP_RULES_ENV];
	if (typeof fpRules === "string" && fpRules.trim().length > 0) {
		context.fpRules = fpRules.trim();
	}

	return context;
}
