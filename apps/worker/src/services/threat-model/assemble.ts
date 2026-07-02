// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Scan-level prompt-context assembler.
 *
 * Reads the per-scan artifacts that frame downstream agents — the threat model
 * and (when present) the historical signal, identity set, and org false-positive
 * rules — and returns a populated {@link PromptContext}. EVERY artifact source is
 * OPTIONAL: a missing/unreadable/empty artifact simply leaves its field unset,
 * which `applyPromptContext` renders as the neutral "(none)" sentinel. The one
 * always-populated field is `targetPosture`: it DEFAULTS to the minimal-impact
 * block and flips to the disposable-target block only on operator opt-in
 * (`SHOR_EXPENDABLE_TARGET`) — destructive exploitation is never the default.
 *
 * NEVER reads or emits credentials. The identity renderer is allowlist-driven
 * (labels/roles only) and the config argument's `authentication.credentials` is
 * deliberately untouched (ADR-050 / auth-context.ts rule).
 */

import { fs, path } from "zx";
import { PROMPTS_DIR } from "../../paths.js";
import type { DistributedConfig } from "../../types/config.js";
import type { PromptContext } from "../prompt-manager/prompt-context.js";
import { renderHistoricalSeed, renderIdentities } from "./artifacts.js";
import { renderThreatModel } from "./render.js";
import { parseThreatModel } from "./schema.js";
import { renderTargetSurface } from "./surface.js";

/** Threat model emitted by the threat-model agent (task 005). */
export const THREAT_MODEL_FILE = "threat_model.json";
/** Prior-exploit hot-spots, produced by task 006. */
export const HISTORICAL_SIGNAL_FILE = "historical_signal.json";
/** Identity labels/roles metadata (NEVER credentials), produced by task 008. */
export const SCAN_IDENTITIES_FILE = "scan_identities.json";
/** Env var carrying org false-positive precedents (task 016). */
export const FP_RULES_ENV = "SHOR_FP_RULES";
/**
 * Operator opt-in (task 003): truthy flips the EXPLOIT/screen posture to
 * disposable-target. DEFAULT (unset/falsey) → minimal-impact; destructive
 * exploitation is NEVER the default.
 */
export const EXPENDABLE_TARGET_ENV = "SHOR_EXPENDABLE_TARGET";
/** Shared prompt file holding the two canned posture blocks (minimal / disposable). */
const TARGET_POSTURE_FILE = "shared/_target-posture.txt";

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

/** Truthy parse mirroring env.ts optionalBool: `1`/`true`/`yes`, case-insensitive. */
function isTruthyFlag(raw: string | undefined): boolean {
	return (
		raw !== undefined && ["1", "true", "yes"].includes(raw.trim().toLowerCase())
	);
}

/**
 * Resolve the `{{TARGET_POSTURE}}` block. Reads the two canned blocks from
 * prompts/shared/_target-posture.txt and returns exactly one: the
 * disposable-target block when `expendable`, otherwise the minimal-impact block
 * (the DEFAULT). A missing/malformed file or absent tag degrades to `undefined`,
 * which renders as the neutral "(none)" sentinel — SAFE, since it never
 * authorizes destruction.
 */
async function selectTargetPosture(
	expendable: boolean,
): Promise<string | undefined> {
	const file = path.join(PROMPTS_DIR, ...TARGET_POSTURE_FILE.split("/"));
	let raw: string;
	try {
		raw = await fs.readFile(file, "utf8");
	} catch {
		return undefined;
	}
	const tag = expendable ? "posture_disposable" : "posture_minimal";
	const match = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`).exec(raw);
	const block = match?.[1]?.trim();
	return block && block.length > 0 ? block : undefined;
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
	webUrl?: string,
): Promise<PromptContext> {
	const environment = env ?? process.env;
	const context: PromptContext = {};

	// Recon-driven target surface: the real service origins recon observed, so
	// agents probe the actual ports (API on :8080, etc.) instead of the SPA at
	// {{WEB_URL}}. Absent until recon's deliverable exists → "(none)" sentinel.
	const surface = await renderTargetSurface(deliverablesPath, webUrl);
	if (surface !== undefined) context.targetSurface = surface;

	const threatModelRaw = await readJsonFile(
		deliverablesPath,
		THREAT_MODEL_FILE,
	);
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

	// Target posture (task 003): DEFAULT minimal-impact; the disposable-target
	// block is selected ONLY when the operator sets SHOR_EXPENDABLE_TARGET truthy.
	const posture = await selectTargetPosture(
		isTruthyFlag(environment[EXPENDABLE_TARGET_ENV]),
	);
	if (posture !== undefined) context.targetPosture = posture;

	return context;
}
