// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Runtime config for the memory wire — the seam that connects the worker's
 * two-tier RAG (retrieve + write) to the pgvector store that lives in apps/web.
 *
 * The worker has NO database access; it reaches the store over the SAME HTTP
 * channel it already uses for the findings sink (`SHOR_FINDINGS_SINK_URL` +
 * `SHOR_SINK_TOKEN`, tenant derived server-side from the scan). So both memory
 * halves run worker-side (embed + fuse + rerank + scrub stay here, where the
 * code and tools live) and only the thin `nearest` / insert DB ops cross to web.
 */

/** Resolved endpoints + auth for the memory wire, or `null` when unconfigured. */
export interface MemoryWireConfig {
	/** `${SHOR_FINDINGS_SINK_URL}/scans/${scanId}/memory` base (no trailing slash). */
	readonly baseUrl: string;
	readonly scanId: string;
	readonly token: string;
	/** Best-effort scope for the store write ctx; web re-derives it authoritatively. */
	readonly tenantId: string;
	readonly projectId: string;
}

/**
 * Read the memory-wire config from the same env the findings sink uses. Returns
 * `null` (memory disabled, fail-open) when the sink URL/token or scan id is
 * absent — exactly the cases where the worker also cannot post findings.
 */
export function readMemoryWireConfig(
	env: NodeJS.ProcessEnv = process.env,
): MemoryWireConfig | null {
	const sinkUrl = env.SHOR_FINDINGS_SINK_URL?.trim();
	const token = env.SHOR_SINK_TOKEN?.trim();
	const scanId = env.SHOR_SCAN_ID?.trim();
	if (!sinkUrl || !token || !scanId) return null;
	return {
		baseUrl: `${sinkUrl.replace(/\/+$/, "")}/scans/${encodeURIComponent(scanId)}/memory`,
		scanId,
		token,
		tenantId: env.SHOR_TENANT_ID?.trim() || "",
		projectId: env.SHOR_PROJECT_ID?.trim() || "",
	};
}
