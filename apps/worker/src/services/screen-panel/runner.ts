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
 * Everything fans out: categories run concurrently, candidates within a category
 * run concurrently, and a candidate's voters run concurrently. A shared
 * {@link SessionPool} — not the loop structure — is what bounds the work: each
 * voter LEASES one of the isolated Playwright sessions for the duration of its
 * run and releases it when done, so total in-flight voters never exceeds the pool
 * size (and the operator can dial that down via GROUP_CONCURRENCY to spare a
 * fragile target). A category failure is isolated: it logs, writes an empty
 * verdicts file (stable fail-open artifact), and the remaining categories
 * continue.
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
import {
	lensesForCategory,
	panelSizeForCategory,
	resolvePanelSize,
} from "./lenses.js";
import {
	createSessionPool,
	SCREEN_SESSIONS,
	type SessionPool,
} from "./session-pool.js";
import type { ScreenVerdictEntry, ScreenVote } from "./types.js";
import { type VoterRunArgs, runVoter } from "./voter.js";

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

/** Default in-flight-voter cap when the caller passes none — the full session pool. */
const DEFAULT_CONCURRENCY = SCREEN_SESSIONS.length;

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

/**
 * Lease a session, run one voter on it, and ALWAYS release — a voter holds a
 * session only for the span of its own run, so the freed slot immediately serves
 * the next waiting voter. `runVoter` never throws (it fails open to an `uncertain`
 * ballot), but the lease is released in a `finally` regardless, so an unexpected
 * throw can never leak a session and starve the pool.
 */
async function runLeasedVoter(
	pool: SessionPool,
	args: Omit<VoterRunArgs, "session">,
): Promise<ScreenVote> {
	const lease = await pool.acquire();
	try {
		return await runVoter({ ...args, session: lease.session });
	} finally {
		lease.release();
	}
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

/** Shared, category-invariant inputs for {@link runCategoryPanel}. Resolved once per phase. */
interface CategoryRunDeps {
	ctx: AgentContext;
	config: DistributedConfig | null;
	panelSize: number;
	pool: SessionPool;
}

/**
 * Run one category's panel: read its candidates, screen every candidate
 * concurrently (each candidate's voters concurrent too), aggregate, and write the
 * verdicts file. The shared lease pool caps total in-flight voters across ALL
 * categories, so this overlaps freely with its siblings. Never throws — a failure
 * is logged and an empty verdicts file is written (the stable fail-open artifact).
 */
async function runCategoryPanel(
	category: string,
	deps: CategoryRunDeps,
): Promise<void> {
	const { ctx, config, pool } = deps;
	const { params, deliverablesPath, container, logger, progress } = ctx;
	// Per-category panel size: ensures a category with an extra lens (authz's
	// auth-context) runs a voter for it instead of leaving it dormant at the
	// default size of 3.
	const panelSize = panelSizeForCategory(category);

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
			return;
		}

		// Render the base screen prompt once per category (lens-agnostic — the
		// lens is layered per voter). Reused across all candidates + voters.
		// Voters get the scan-wide assembled context (threat model, identities,
		// FP rules) so the diverse-lens verification is context-aware, not blind.
		const deliverablesSubdir = path.relative(params.repoPath, deliverablesPath);
		const providerConfig = container.config.providerConfig;
		const promptContext = await assembleScanPromptContext(
			deliverablesPath,
			config,
			process.env,
			params.targetUrl,
		);
		const basePrompt = await loadPrompt(
			def.promptTemplate,
			{ webUrl: params.targetUrl, repoPath: params.repoPath },
			config,
			logger,
			undefined,
			promptContext,
		);

		// Every candidate is screened concurrently; within a candidate every voter
		// runs concurrently too. None of this oversubscribes the browser pool — each
		// voter leases a session for its run, so the pool size is the real bound.
		const entries: ScreenVerdictEntry[] = await Promise.all(
			candidates.map(async (candidateId): Promise<ScreenVerdictEntry> => {
				const lenses = lensesForCategory(category, panelSize);
				const votes = await Promise.all(
					lenses.map((lens, i) =>
						runLeasedVoter(pool, {
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
					),
				);
				return buildVerdictEntry(candidateId, votes);
			}),
		);

		writeVerdicts(deliverablesPath, category, entries, logger);
		await progress.completed_(screenAgent, Date.now() - startedAt);
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
		await progress.failed(screenAgent, Date.now() - startedAt);
	}
}

/**
 * Run the diverse-lens screen panel for every category, in place of the single
 * screen agent. `concurrency` caps how many voters run at once across the WHOLE
 * phase (the pipeline passes its GROUP_CONCURRENCY); it is clamped to the number
 * of isolated screen sessions, since a voter needs one to itself. Categories,
 * candidates, and voters all fan out concurrently; the lease pool is the throttle.
 * Resilient: a per-category failure is logged and isolated; the phase never throws.
 */
export async function runScreenPanel(
	ctx: AgentContext,
	concurrency: number = DEFAULT_CONCURRENCY,
): Promise<void> {
	const { params, container, logger } = ctx;
	const panelSize = resolvePanelSize(process.env);

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

	// Size the lease pool to the in-flight-voter cap, bounded by the number of
	// isolated sessions (each voter holds one) and floored at 1. This is the single
	// throttle for the whole fan-out below.
	const poolSize = Math.max(
		1,
		Math.min(SCREEN_SESSIONS.length, Math.floor(concurrency)),
	);
	const pool = createSessionPool(SCREEN_SESSIONS.slice(0, poolSize));

	logger.info("screen-panel: starting N-vote diverse-lens screen", {
		scanId: params.scanId,
		voters: panelSize,
		sessions: poolSize,
	});

	// Categories fan out; runCategoryPanel never throws, so one failure can't abort
	// the rest. The pool keeps total concurrent voters within poolSize regardless.
	await Promise.all(
		SCREEN_CATEGORIES.map((category) =>
			runCategoryPanel(category, { ctx, config, panelSize, pool }),
		),
	);
}
