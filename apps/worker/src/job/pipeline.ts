// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * In-process phased pipeline runner for the Cloud Run Job entrypoint (ADR-051).
 *
 * The inverted worker model drops per-scan `bundleWorkflowCode` and the self-
 * submitting Temporal worker: the Job runs the pipeline directly, driving each
 * agent through the same service layer the Temporal activities use
 * (`Container.agentExecution`). Agents run in canonical order; each gets its own
 * `AuditSession` (per-agent instance state cannot be shared).
 */

import { AuditSession } from "../audit/index.js";
import { deliverablesDir } from "../paths.js";
import { getOrCreateContainer } from "../services/container.js";
import { AGENTS } from "../session-manager.js";
import type { Container } from "../services/container.js";
import type { AgentName } from "../types/agents.js";
import type { ActivityLogger } from "../types/activity-logger.js";
import type { SessionMetadata } from "../types/audit.js";
import type { ScanJobParams } from "./env.js";
import { bootstrapIdentities } from "../services/identity/index.js";
import { runOraclePhase } from "../services/oracle/index.js";
import { runScreenPanel } from "../services/screen-panel/index.js";
import {
	restoreCheckpoint,
	saveCheckpoint,
} from "../services/checkpoint/index.js";
import { reportFindings } from "./findings/index.js";
import { recordExploitLaneOutcome } from "./findings/lane-status.js";
import { ProgressEmitter } from "./progress/index.js";

/**
 * Pipeline stages (ADR-051). pre-recon and recon are prerequisites and run
 * sequentially (fail-fast — the vuln agents read their deliverables). The vuln and
 * exploit agents are each mutually independent within their group, so each group
 * runs CONCURRENTLY (2-wide — keeps us under the flash rate limit and ~2 headless
 * browsers within the job's RAM). Between discovery and exploitation runs the
 * adversarial screen PANEL (T8 + T11): per category, each candidate hypothesis is
 * judged by N independent lens-voters (blind to recon context) whose structured
 * verdicts aggregate by majority, so the exploit agents receive a pre-filtered,
 * higher-confidence queue. Within a group an agent failure is isolated (logged,
 * the others continue); report + attack-surface are best-effort synthesis.
 */
const PREREQ_AGENTS: readonly AgentName[] = ["pre-recon", "recon", "threat-model"];
const VULN_AGENTS: readonly AgentName[] = ["injection-vuln", "xss-vuln", "auth-vuln", "ssrf-vuln", "authz-vuln", "logic-vuln", "misconfig-web-vuln"];
const EXPLOIT_AGENTS: readonly AgentName[] = ["injection-exploit", "xss-exploit", "auth-exploit", "ssrf-exploit", "authz-exploit", "logic-exploit", "misconfig-web-exploit"];
const SYNTHESIS_AGENTS: readonly AgentName[] = ["report", "attack-surface"];

/**
 * Effective parallel-group width (vuln / screen / exploit). Unset config → FULL
 * width — every agent in the group at once. DeepSeek flash allows ~2500 concurrent
 * requests, so the LLM is not the bound; the old 2-wide cap was a RAM/rate guess
 * that no longer applies. `SHOR_GROUP_CONCURRENCY` dials it down (e.g. to spare a
 * fragile target). Clamped to the group size.
 */
export function resolveGroupWidth(
	configured: number | undefined,
	groupSize: number,
): number {
	if (configured !== undefined && configured > 0) {
		return Math.min(configured, groupSize);
	}
	return groupSize;
}

/** Per-agent metrics summary returned to the entrypoint. */
export interface AgentRunSummary {
	agent: AgentName;
	durationMs: number;
}

/** Outcome of one scan pipeline run. */
export interface PipelineRunResult {
	scanId: string;
	completedAgents: AgentRunSummary[];
}

/**
 * Per-scan context threaded through every agent run and the oracle phase.
 * Exported so post-exploit phase services (e.g. `runOraclePhase`) can receive it
 * without re-deriving the container/paths.
 */
export interface AgentContext {
	params: ScanJobParams;
	deliverablesPath: string;
	container: Container;
	sessionMetadata: SessionMetadata;
	progress: ProgressEmitter;
	completedAgents: AgentRunSummary[];
	logger: ActivityLogger;
}

/** Run one agent: own AuditSession, execute, emit progress, push partial findings. Throws on failure. */
async function runAgent(agentName: AgentName, ctx: AgentContext): Promise<void> {
	const { params, deliverablesPath, container, sessionMetadata, progress, completedAgents, logger } = ctx;
	logger.info(`Starting agent ${agentName}`, { phase: AGENTS[agentName].displayName, scanId: params.scanId });
	await progress.started(agentName);

	const auditSession = new AuditSession(sessionMetadata);
	await auditSession.initialize(params.scanId);

	const started = Date.now();
	try {
		const endResult = await container.agentExecution.executeOrThrow(
			agentName,
			{
				webUrl: params.targetUrl,
				repoPath: params.repoPath,
				deliverablesPath,
				attemptNumber: 1,
				...(params.configPath !== undefined && { configPath: params.configPath }),
				...(params.configYaml !== undefined && { configYAML: params.configYaml }),
			},
			auditSession,
			logger,
			container,
		);
		const durationMs = endResult.duration_ms || Date.now() - started;
		completedAgents.push({ agent: agentName, durationMs });
		await progress.completed_(agentName, durationMs);
		logger.info(`Completed agent ${agentName}`, { durationMs });
	} catch (err) {
		await progress.failed(agentName, Date.now() - started);
		throw err;
	} finally {
		// Push cumulative findings after each agent (status stays `running`) so a
		// timeout/OOM kill never loses results.
		await reportFindings(deliverablesPath, params.scanId, "running", logger);
	}
}

/**
 * Run `agents` with at most `concurrency` in flight; an agent failure is isolated
 * (logged), the rest continue. For EXPLOIT_AGENTS we also record the per-category
 * validation-lane outcome (T5): a clean completion marks the lane `validated`, a
 * THROW marks it `failed` so its non-exploited findings are demoted out of the
 * emitted set by the findings gate. `recordExploitLaneOutcome` no-ops for any
 * non-exploit agent, so it is safe to call here for every agent in the group.
 */
async function runGroup(agents: readonly AgentName[], concurrency: number, ctx: AgentContext): Promise<void> {
	const queue = [...agents];
	const worker = async (): Promise<void> => {
		for (let next = queue.shift(); next; next = queue.shift()) {
			try {
				await runAgent(next, ctx);
				recordExploitLaneOutcome(ctx.deliverablesPath, next, "validated", ctx.logger);
			} catch (err) {
				recordExploitLaneOutcome(ctx.deliverablesPath, next, "failed", ctx.logger);
				ctx.logger.error(`Agent ${next} failed; group continues`, {
					scanId: ctx.params.scanId,
					error: err instanceof Error ? err.message : String(err),
				});
			}
		}
	};
	await Promise.all(Array.from({ length: Math.min(concurrency, agents.length) }, worker));
}

/**
 * Run the full agent pipeline for one scan in-process. Prerequisites are
 * fail-fast (throw → the Job exits non-zero → scan `failed`); the vuln/exploit
 * groups and synthesis are resilient (a single agent failure does not abort the
 * run). Returns the per-agent metrics.
 */
export async function runScanPipeline(
	params: ScanJobParams,
	logger: ActivityLogger,
): Promise<PipelineRunResult> {
	const sessionMetadata: SessionMetadata = {
		id: params.scanId,
		webUrl: params.targetUrl,
		repoPath: params.repoPath,
	};

	const container = getOrCreateContainer(params.scanId, sessionMetadata);
	const deliverablesPath = deliverablesDir(params.repoPath, container.config.deliverablesSubdir);

	// Resume: if a checkpoint exists for this scanId, restore its deliverables and
	// learn which phases already finished, so the guarded phases below skip them.
	// No-op (empty set) when checkpointing is unwired or there is no prior run.
	const completedPhases = restoreCheckpoint(
		params.scanId,
		deliverablesPath,
		logger,
	);

	const completedAgents: AgentRunSummary[] = [];
	const ctx: AgentContext = {
		params,
		deliverablesPath,
		container,
		sessionMetadata,
		progress: new ProgressEmitter(params.scanId, logger),
		completedAgents,
		logger,
	};

	// Parallel-group width: full by default (all agents at once), or the
	// operator-set SHOR_GROUP_CONCURRENCY. Applies to vuln / screen / exploit.
	const groupWidth = resolveGroupWidth(
		params.groupConcurrency,
		VULN_AGENTS.length,
	);
	logger.info("Parallel-group width", {
		scanId: params.scanId,
		groupWidth,
		configured: params.groupConcurrency ?? "full",
	});

	// 0) Multi-identity bootstrap (task 008) — provision per-identity session slots
	// and write scan_identities.json BEFORE the prereq loop, so even threat-model
	// sees the identity set. Best-effort: bootstrapIdentities never throws, but we
	// wrap defensively so a surprise fault here can never abort the scan.
	try {
		await bootstrapIdentities(ctx);
	} catch (err) {
		logger.error("Identity bootstrap threw unexpectedly; continuing", {
			scanId: params.scanId,
			error: err instanceof Error ? err.message : String(err),
		});
	}

	// 1) Prerequisites — sequential, fail-fast (vuln agents depend on these).
	if (completedPhases.has("prereq")) {
		logger.info("checkpoint: skipping completed phase", { phase: "prereq" });
	} else {
		for (const agentName of PREREQ_AGENTS) {
			await runAgent(agentName, ctx);
		}
		saveCheckpoint(params.scanId, "prereq", deliverablesPath, logger);
	}

	// 2) Vulnerability analysis → adversarial screen panel → exploitation. The vuln
	// and exploit groups are each 2-wide and fault-isolated. The screen step is no
	// longer one agent per category but an N-vote diverse-lens panel (T8 + T11):
	// per candidate, N independent lens-voters emit structured verdicts that
	// aggregate by majority into `{category}_screen_verdicts.json`. The exploit pass
	// then works from a pre-filtered, higher-confidence queue (T6). Voters run with
	// the same GROUP_CONCURRENCY bound.
	if (completedPhases.has("vuln")) {
		logger.info("checkpoint: skipping completed phase", { phase: "vuln" });
	} else {
		await runGroup(VULN_AGENTS, groupWidth, ctx);
		saveCheckpoint(params.scanId, "vuln", deliverablesPath, logger);
	}
	if (completedPhases.has("screen")) {
		logger.info("checkpoint: skipping completed phase", { phase: "screen" });
	} else {
		await runScreenPanel(ctx, groupWidth);
		saveCheckpoint(params.scanId, "screen", deliverablesPath, logger);
	}
	if (completedPhases.has("exploit")) {
		logger.info("checkpoint: skipping completed phase", { phase: "exploit" });
	} else {
		await runGroup(EXPLOIT_AGENTS, groupWidth, ctx);
		saveCheckpoint(params.scanId, "exploit", deliverablesPath, logger);
	}

	// 2b) Oracle phase — post-exploitation adjudication over the exploited/screened
	// dispositions. No-op today (task 013 fills `runOraclePhase`); runs before
	// synthesis so the report/attack-surface see the adjudicated set.
	if (completedPhases.has("oracle")) {
		logger.info("checkpoint: skipping completed phase", { phase: "oracle" });
	} else {
		await runOraclePhase(ctx);
		saveCheckpoint(params.scanId, "oracle", deliverablesPath, logger);
	}

	// 3) Synthesis — best-effort; a failure here must not discard the findings.
	for (const agentName of SYNTHESIS_AGENTS) {
		try {
			await runAgent(agentName, ctx);
		} catch (err) {
			logger.error(`Synthesis agent ${agentName} failed; continuing`, {
				scanId: params.scanId,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}

	return { scanId: params.scanId, completedAgents };
}
