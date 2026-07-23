// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The pipeline-facing entry point for RAG retrieval — the "recall" half wired
 * into the per-agent prompt build (`pre-execution.ts`). For a category agent it
 * builds a semantic query from the agent's bug class plus the assembled scan
 * context, recalls the top exemplars from both memory tiers over HTTP, and
 * returns the rendered `{{RAG_EXEMPLARS}}` block.
 *
 * ALWAYS FAIL-OPEN: any failure (no embedder, no sink config, store error)
 * returns `null` and the caller leaves the prompt unchanged. Retrieval never
 * throws into the scan pipeline.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import type { AgentName } from "../../../types/agents.js";
import type { PromptContext } from "../../prompt-manager/prompt-context.js";
import { createEmbedClient } from "../embed/index.js";
import { retrieveExemplars } from "../retrieve/index.js";
import type { RetrievalQuery, RetrieveDeps } from "../retrieve/types.js";
import { readMemoryWireConfig } from "./config.js";
import { createHttpGlobalPort, createHttpLocalPort } from "./http-ports.js";

/** Human-readable descriptor per bug class, seeding the semantic query text. */
const CATEGORY_LABELS: Record<string, string> = {
	injection: "SQL, NoSQL, command and template injection",
	xss: "cross-site scripting (XSS), DOM and stored/reflected",
	auth: "authentication, session and credential weaknesses",
	ssrf: "server-side request forgery (SSRF) and blind SSRF",
	authz: "broken access control, authorization bypass and IDOR",
	logic: "business-logic flaws and workflow abuse",
	"misconfig-web": "web security misconfiguration and exposure",
};

/** Strip the phase suffix to get the bug class (`xss-vuln` -> `xss`). */
function categoryOf(agentName: string): string | null {
	const m = /^(.*)-(vuln|exploit)$/.exec(agentName);
	return m?.[1] ?? null;
}

/** Cap the extra context appended to the query so embedding stays cheap. */
const MAX_CONTEXT_CHARS = 1500;

/** Build the retrieval query from the agent's class + the assembled scan context. */
function buildQuery(
	category: string,
	context: PromptContext,
): RetrievalQuery {
	const label = CATEGORY_LABELS[category] ?? category;
	const extra = [context.targetSurface, context.threatModel]
		.filter((s): s is string => typeof s === "string" && s.trim() !== "")
		.join("\n")
		.slice(0, MAX_CONTEXT_CHARS);
	const text = extra ? `${label}\n${extra}` : label;
	return { text, terms: [category, ...label.split(/[\s,()]+/).filter(Boolean)] };
}

/**
 * Retrieve the RAG exemplars for a category agent, or `null` when retrieval is
 * off, unconfigured, or empty. Only vuln/exploit category agents query memory;
 * recon/threat-model/report agents return `null` (their prompts have no
 * `{{RAG_EXEMPLARS}}` slot). Best-effort and fail-open.
 */
export async function retrieveRagForAgent(
	agentName: AgentName,
	context: PromptContext,
	env: NodeJS.ProcessEnv = process.env,
	logger?: ActivityLogger,
): Promise<string | null> {
	const category = categoryOf(agentName);
	if (!category) return null;

	const cfg = readMemoryWireConfig(env);
	if (!cfg) return null;

	try {
		const embed = createEmbedClient();
		if (!embed.enabled) return null;

		const deps: RetrieveDeps = {
			embed,
			local: createHttpLocalPort(cfg),
			global: createHttpGlobalPort(cfg),
			logger,
		};
		const scope = { tenantId: cfg.tenantId || cfg.scanId, projectId: cfg.projectId };
		const { rendered, exemplars } = await retrieveExemplars(
			buildQuery(category, context),
			scope,
			deps,
		);
		if (rendered) {
			logger?.info("rag-retrieve: exemplars injected", {
				agent: agentName,
				count: exemplars.length,
			});
		}
		return rendered;
	} catch (err) {
		logger?.warn("rag-retrieve: failed — prompt left unchanged", {
			agent: agentName,
			reason: err instanceof Error ? err.message : String(err),
		});
		return null;
	}
}
