// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * POST findings to the dashboard sink, per the shared contract:
 *   POST `${SHOR_FINDINGS_SINK_URL}/scans/${SHOR_SCAN_ID}/findings`
 *   Authorization: Bearer ${SHOR_SINK_TOKEN}
 *   body: { findings, attackSurface?, status }
 *
 * Best-effort: a missing sink config or a failed request is logged (never with
 * the token) and swallowed — the Job's exit code is driven by the pipeline, not
 * by the dashboard handoff.
 */

import type { ActivityLogger } from "../../types/activity-logger.js";
import type { FindingsSinkPayload } from "./types.js";

export interface SinkConfig {
	baseUrl: string;
	token: string;
	scanId: string;
}

/** Read sink config from env; returns undefined if not fully configured. */
export function readSinkConfig(scanId: string): SinkConfig | undefined {
	const baseUrl = process.env.SHOR_FINDINGS_SINK_URL?.trim();
	const token = process.env.SHOR_SINK_TOKEN?.trim();
	if (!baseUrl || !token) return undefined;
	return { baseUrl: baseUrl.replace(/\/+$/, ""), token, scanId };
}

/**
 * POST the payload to the sink. Resolves to `true` on a 2xx response, `false`
 * otherwise. NEVER throws — failures are logged and reported via the return.
 * The bearer token is never logged.
 */
export async function postFindings(
	config: SinkConfig,
	payload: FindingsSinkPayload,
	logger: ActivityLogger,
): Promise<boolean> {
	const url = `${config.baseUrl}/scans/${encodeURIComponent(config.scanId)}/findings`;
	try {
		const res = await fetch(url, {
			method: "POST",
			headers: {
				"content-type": "application/json",
				authorization: `Bearer ${config.token}`,
			},
			body: JSON.stringify(payload),
		});
		if (!res.ok) {
			logger.error("Findings sink returned non-2xx", {
				scanId: config.scanId,
				httpStatus: res.status,
				findingsCount: payload.findings.length,
				status: payload.status,
			});
			return false;
		}
		logger.info("Findings posted to sink", {
			scanId: config.scanId,
			httpStatus: res.status,
			findingsCount: payload.findings.length,
			status: payload.status,
		});
		return true;
	} catch (err) {
		logger.error("Failed to POST findings to sink", {
			scanId: config.scanId,
			error: err instanceof Error ? err.message : String(err),
			findingsCount: payload.findings.length,
			status: payload.status,
		});
		return false;
	}
}
