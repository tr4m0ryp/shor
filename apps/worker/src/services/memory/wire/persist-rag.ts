// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * The pipeline-facing entry point for the RAG "remember" half — wired into the
 * findings emission at scan finalize. For each finalized finding it verbalizes,
 * runs the MANDATORY fail-closed scrub (secrets + PII), embeds, and upserts the
 * project-local memory tier over HTTP so the next scan of this target recalls it.
 *
 * ALWAYS BEST-EFFORT: the whole pass is wrapped fail-open. A scrub failure skips
 * only that one finding; any store/embed error is logged and swallowed. Memory
 * writes NEVER affect the findings emission or the scan outcome.
 */

import type { ActivityLogger } from "../../../types/activity-logger.js";
import { createEmbedClient } from "../embed/index.js";
import type { FindingLike } from "../schema/index.js";
import {
	createBuiltinPiiAnalyzer,
	createGitleaksDetector,
	createTrufflehogDetector,
	type ScrubDeps,
} from "../scrub/index.js";
import { persistFindings } from "../write/index.js";
import {
	createHttpEmbeddingWriter,
	createHttpFpMemoryWriter,
} from "./http-ports.js";
import { readMemoryWireConfig } from "./config.js";

/** Secret + PII scrub built on the tools the worker image already ships. */
function buildScrubDeps(logger?: ActivityLogger): ScrubDeps {
	return {
		secretDetectors: [createGitleaksDetector(), createTrufflehogDetector()],
		piiAnalyzers: [createBuiltinPiiAnalyzer()],
		piiEngine: "builtin",
		logger,
	};
}

/**
 * Persist a scan's finalized findings into the learning-memory local tier.
 * No-op (returns silently) when memory is unconfigured, the embedder is absent,
 * or there are no findings. Summarizes how many were stored vs skipped.
 */
export async function persistFindingsToMemory(
	findings: readonly unknown[],
	env: NodeJS.ProcessEnv = process.env,
	logger?: ActivityLogger,
): Promise<void> {
	if (findings.length === 0) return;
	const cfg = readMemoryWireConfig(env);
	if (!cfg) return;

	try {
		const embed = createEmbedClient();
		if (!embed.enabled) return;

		const outcomes = await persistFindings(
			findings as readonly FindingLike[],
			{ tenantId: cfg.tenantId, projectId: cfg.projectId, scanId: cfg.scanId },
			{
				embed,
				scrubDeps: buildScrubDeps(logger),
				embeddings: createHttpEmbeddingWriter(cfg),
				fpMemory: createHttpFpMemoryWriter(cfg),
				logger,
			},
		);
		const stored = outcomes.filter((o) => o.written).length;
		logger?.info("rag-write: findings persisted to memory", {
			stored,
			skipped: outcomes.length - stored,
		});
	} catch (err) {
		logger?.warn("rag-write: failed — findings NOT persisted to memory", {
			reason: err instanceof Error ? err.message : String(err),
		});
	}
}
