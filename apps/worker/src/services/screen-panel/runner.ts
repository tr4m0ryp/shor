// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Screen-panel phase runner (T8 + T11). Replaces the single adversarial-screen
 * agent per category with an N-vote diverse-lens panel.
 *
 * For each screen category it reads the category's exploitation queue, then runs
 * an N-voter panel per candidate (each voter a distinct lens + isolated
 * Playwright session) and aggregates the ballots by majority into
 * `<deliverablesPath>/{category}_screen_verdicts.json` — the stable artifact
 * task 012 reads for fail-open routing.
 *
 * Candidates run one at a time so the panel's N voters never oversubscribe the
 * 5-session Playwright pool; within a candidate the voters run with bounded
 * concurrency (the pipeline's GROUP_CONCURRENCY, passed in). A category failure
 * is isolated: it logs, writes an empty verdicts file (stable fail-open
 * artifact), and the remaining categories continue.
 */

import fs from "node:fs";
import path from "node:path";
import type { AgentContext } from "../../job/pipeline.js";
import { AGENTS } from "../../session-manager.js";
import type { ActivityLogger } from "../../types/activity-logger.js";
import type { AgentName } from "../../types/agents.js";
import type { DistributedConfig } from "../../types/config.js";
import { isErr } from "../../types/result.js";
import { loadPrompt } from "../prompt-manager.js";
import { assembleScanPromptContext } from "../threat-model/index.js";
import { buildVerdictEntry } from "./aggregate.js";
import { lensesForCategory, resolvePanelSize } from "./lenses.js";
import type { ScreenVerdictEntry, ScreenVote } from "./types.js";
import { runVoter } from "./voter.js";

/** Categories with a screen agent — the panel covers each `{category}-screen`. */
const SCREEN_CATEGORIES = [
	"injection",
	"xss",
	"auth",
	"ssrf",
	"authz",
	"logic",
	"misconfig-web",
] as const;

/** Default voter concurrency when the caller passes none (mirrors GROUP_CONCURRENCY). */
const DEFAULT_CONCURRENCY = 2;

/**
 * Read the candidate ids from a `{category}_exploitation_queue.json` file. Mirrors
 * `job/findings/queue.normalizeQueue`'s id resolution (including the
 * `${CATEGORY}-VULN-NN` synthesized fallback) so panel verdict ids line up with
 * the normalized queue task 012 routes against. Missing/malformed → no candidates.
 */
function readCandidateIds(
	file: string,
	category: string,
	logger: ActivityLogger,
): string[] {
	try {
		if (!fs.existsSync(file)) return [];
		const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
		const items =
			parsed !== null &&
			typeof parsed === "object" &&
			Array.isArray((parsed as { vulnerabilities?: unknown }).vulnerabilities)
				? (parsed as { vulnerabilities: unknown[] }).vulnerabilities
				: [];
		const ids: string[] = [];
		for (let i = 0; i < items.length; i++) {
			const rec = items[i];
			if (rec === null || typeof rec !== "object") continue;
			const idRaw = (rec as Record<string, unknown>).ID;
			const id =
				typeof idRaw === "string" && idRaw.trim() !== ""
					? idRaw.trim()
					: `${category.toUpperCase()}-VULN-${String(i + 1).padStart(2, "0")}`;
			ids.push(id);
		}
		return ids;
	} catch (err) {
		logger.warn("screen-panel: failed to read exploitation queue; no candidates", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
		return [];
	}
}

/** Run an array of voter thunks with at most `limit` in flight; ballots returned voter-ordered. */
async function runBounded(
	thunks: readonly (() => Promise<ScreenVote>)[],
	limit: number,
): Promise<ScreenVote[]> {
	const queue = [...thunks];
	const collected: ScreenVote[] = [];
	const worker = async (): Promise<void> => {
		for (let job = queue.shift(); job !== undefined; job = queue.shift()) {
			collected.push(await job());
		}
	};
	const count = Math.max(1, Math.min(limit, thunks.length));
	await Promise.all(Array.from({ length: count }, () => worker()));
	collected.sort((a, b) => a.voter - b.voter);
	return collected;
}

/** Atomically-ish write a category's verdict array (pretty-printed for diffable audits). */
function writeVerdicts(
	deliverablesPath: string,
	category: string,
	entries: ScreenVerdictEntry[],
	logger: ActivityLogger,
): void {
	const out = path.join(deliverablesPath, `${category}_screen_verdicts.json`);
	try {
		fs.writeFileSync(out, JSON.stringify(entries, null, 2));
	} catch (err) {
		logger.error("screen-panel: failed to write verdicts file", {
			out,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}

/**
 * Run the diverse-lens screen panel for every category, in place of the single
 * screen agent. `concurrency` bounds the in-flight voters per candidate (the
 * pipeline passes its GROUP_CONCURRENCY). Resilient: a per-category failure is
 * logged and isolated; the phase never throws.
 */
export async function runScreenPanel(
	ctx: AgentContext,
	concurrency: number = DEFAULT_CONCURRENCY,
): Promise<void> {
	const { params, deliverablesPath, container, logger, progress } = ctx;
	const panelSize = resolvePanelSize(process.env);
	const deliverablesSubdir = path.relative(params.repoPath, deliverablesPath);
	const providerConfig = container.config.providerConfig;

	// Resolve the distributed config once (login/rules/auth-context render the same
	// for every voter). A parse failure falls open to null — voters still run.
	const configResult = await container.configLoader.loadOptional(
		params.configPath,
		undefined,
		params.configYaml,
	);
	const config: DistributedConfig | null = isErr(configResult)
		? null
		: configResult.value;
	if (isErr(configResult)) {
		logger.warn("screen-panel: config load failed; rendering prompts without it", {
			error: configResult.error.message,
		});
	}

	logger.info("screen-panel: starting N-vote diverse-lens screen", {
		scanId: params.scanId,
		voters: panelSize,
		concurrency,
	});

	for (const category of SCREEN_CATEGORIES) {
		// Emit progress per screen agent so the dashboard shows the adversarial-screen
		// phase running and the timeline advances (the panel runs outside the normal
		// runAgent path that emits these). Declared before the try so catch can report.
		const screenAgent = `${category}-screen` as AgentName;
		const startedAt = Date.now();
		await progress.started(screenAgent);
		try {
			const def = AGENTS[screenAgent];
			const queueFile = path.join(
				deliverablesPath,
				`${category}_exploitation_queue.json`,
			);
			const candidates = readCandidateIds(queueFile, category, logger);
			if (candidates.length === 0) {
				writeVerdicts(deliverablesPath, category, [], logger);
				await progress.completed_(screenAgent, Date.now() - startedAt);
				continue;
			}

			// Render the base screen prompt once per category (lens-agnostic — the
			// lens is layered per voter). Reused across all candidates + voters.
			// Voters get the scan-wide assembled context (threat model, identities,
			// FP rules) so the diverse-lens verification is context-aware, not blind.
			const promptContext = await assembleScanPromptContext(
				deliverablesPath,
				config,
				process.env,
			);
			const basePrompt = await loadPrompt(
				def.promptTemplate,
				{ webUrl: params.targetUrl, repoPath: params.repoPath },
				config,
				logger,
				undefined,
				promptContext,
			);

			const entries: ScreenVerdictEntry[] = [];
			for (const candidateId of candidates) {
				const lenses = lensesForCategory(category, panelSize);
				const thunks = lenses.map(
					(lens, i) => (): Promise<ScreenVote> =>
						runVoter({
							basePrompt,
							candidateId,
							lens,
							voter: i + 1,
							sourceDir: params.repoPath,
							deliverablesSubdir,
							modelTier: def.modelTier ?? "medium",
							agentLabel: def.name,
							logger,
							...(providerConfig !== undefined ? { providerConfig } : {}),
						}),
				);
				const votes = await runBounded(thunks, concurrency);
				entries.push(buildVerdictEntry(candidateId, votes));
			}

			writeVerdicts(deliverablesPath, category, entries, logger);
			logger.info("screen-panel: category complete", {
				category,
				candidates: candidates.length,
				voters: panelSize,
			});
		} catch (err) {
			logger.error("screen-panel: category failed; writing empty verdicts", {
				category,
				error: err instanceof Error ? err.message : String(err),
			});
			writeVerdicts(deliverablesPath, category, [], logger);
		}
	}
}
