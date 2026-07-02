// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Shared workflow execution context for the Storron pentest pipeline.
 *
 * Centralises the activity proxies, activity input, mutable pipeline state,
 * and small predicate/wait helpers that every phase needs. Phase modules
 * accept a `PipelineContext` argument instead of closing over private
 * variables, which keeps state threading explicit and avoids spawning new
 * closures inside the workflow sandbox.
 */

import { condition, log, proxyActivities } from "@temporalio/workflow";
import type * as activities from "../activities.js";
import type { ActivityInput } from "../activities.js";
import type { PipelineInput, PipelineState, ResumeState } from "../shared.js";
import {
	BASE_ACTS_OPTIONS,
	BASE_PREFLIGHT_OPTIONS,
	BASE_SUBSCRIPTION_ACTS_OPTIONS,
} from "../workflows-config.js";

type Activities = typeof activities;
export type ActivityProxy = ReturnType<typeof proxyActivities<Activities>>;

/** Bundle of activity proxies tuned for different retry/timeout profiles. */
export interface ActivityProxies {
	acts: ActivityProxy;
	subscriptionActs: ActivityProxy;
	preflightActs: ActivityProxy;
}

/** Mutable execution context shared between phase modules. */
export interface PipelineContext {
	input: PipelineInput;
	workflowId: string;
	state: PipelineState;
	activityInput: ActivityInput;
	proxies: ActivityProxies;
	/** Active activity proxy chosen by retry preset (subscription vs default). */
	a: ActivityProxy;
	/** Resume metadata; populated only when resuming from a prior workspace. */
	resumeState: ResumeState | null;
}

/**
 * Build all three activity proxies from their base timeout/retry profiles.
 * The `input` parameter is retained for interface stability with callers.
 */
export function buildActivityProxies(_input: PipelineInput): ActivityProxies {
	const acts = proxyActivities<Activities>(BASE_ACTS_OPTIONS);
	const subscriptionActs = proxyActivities<Activities>(
		BASE_SUBSCRIPTION_ACTS_OPTIONS,
	);
	const preflightActs = proxyActivities<Activities>(BASE_PREFLIGHT_OPTIONS);

	return { acts, subscriptionActs, preflightActs };
}

/** Select activity proxy based on retry preset: subscription (extended) or default. */
export function selectActivityProxy(
	input: PipelineInput,
	proxies: ActivityProxies,
): ActivityProxy {
	if (input.pipelineConfig?.retry_preset === "subscription")
		return proxies.subscriptionActs;
	return proxies.acts;
}

/**
 * Build ActivityInput with required workflowId for audit correlation.
 * Activities require workflowId (non-optional); PipelineInput has it optional.
 * Uses spread to conditionally include optional properties (exactOptionalPropertyTypes).
 * sessionId is workspace name for resume, or workflowId for new runs.
 */
export function buildActivityInput(
	input: PipelineInput,
	workflowId: string,
): ActivityInput {
	const sessionId = input.sessionId || input.resumeFromWorkspace || workflowId;

	return {
		webUrl: input.webUrl,
		repoPath: input.repoPath,
		workflowId,
		sessionId,
		...(input.configPath !== undefined && { configPath: input.configPath }),
		...(input.outputPath !== undefined && { outputPath: input.outputPath }),
		...(input.configYAML !== undefined && { configYAML: input.configYAML }),
		...(input.apiKey !== undefined && { apiKey: input.apiKey }),
		...(input.deliverablesSubdir !== undefined && {
			deliverablesSubdir: input.deliverablesSubdir,
		}),
		...(input.auditDir !== undefined && { auditDir: input.auditDir }),
		...(input.promptDir !== undefined && { promptDir: input.promptDir }),
		...(input.sastSarifPath !== undefined && {
			sastSarifPath: input.sastSarifPath,
		}),
		...(input.skipGitCheck !== undefined && {
			skipGitCheck: input.skipGitCheck,
		}),
		...(input.providerConfig !== undefined && {
			providerConfig: input.providerConfig,
		}),
	};
}

/** Predicate: should this agent be skipped because the resumed run already finished it? */
export function shouldSkip(ctx: PipelineContext, agentName: string): boolean {
	return ctx.resumeState?.completedAgents.includes(agentName) ?? false;
}

/**
 * Block until the workflow is resumed if a pause signal was received.
 * No-op when the workflow is running normally.
 */
export async function waitIfPaused(ctx: PipelineContext): Promise<void> {
	if (!ctx.state.paused) return;
	log.info("Workflow paused, waiting for resume signal");
	await condition(() => !ctx.state.paused);
	log.info("Workflow resumed");
}
