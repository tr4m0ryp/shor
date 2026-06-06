// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-kind replay executors.
 *
 * `httpExecutor` is the in-process deterministic path: every outbound request is
 * wrapped by the network guard FIRST (default-deny egress, metadata/internal
 * blocked, RoE scope) and only then issued via the worker's `fetch`. The browser
 * and OOB executors are SEAMS: the worker process has no in-process browser /
 * interactsh harness (and no new deps may be added), so they default to
 * `not_replayable` — leaving the markdown-parse fallback authoritative for those
 * findings. A later session can inject real runners via {@link ExecutorSet}
 * without touching the runner or the read-only gate.
 */

import type { ExecOutcome, Executor, ExecutorSet } from "./types.js";

/** Cap the body we read so a huge response cannot exhaust memory. */
const MAX_BODY_CHARS = 64 * 1024;

/** Replay a read-only HTTP PoC and report the observed status + body. */
export const httpExecutor: Executor = async (poc, ctx): Promise<ExecOutcome> => {
	const req = poc.request;
	if (!req || typeof req.url !== "string" || req.url === "") {
		return { observed: false, reason: "not_replayable", detail: "http PoC has no request.url" };
	}

	// SAFETY: the network guard wraps EVERY outbound request, before any fetch.
	try {
		ctx.assertAllowed(req.url);
	} catch (err) {
		return {
			observed: false,
			reason: "not_replayable",
			detail: `network guard blocked: ${err instanceof Error ? err.message : String(err)}`,
		};
	}

	const method = (req.method ?? "GET").toUpperCase();
	const init: RequestInit = {
		method,
		...(req.headers && { headers: req.headers }),
		...(req.body !== undefined && method !== "GET" && method !== "HEAD" && { body: req.body }),
	};

	const controller = new AbortController();
	const timer = ctx.timeoutMs > 0 ? setTimeout(() => controller.abort(), ctx.timeoutMs) : undefined;
	let res: Response;
	try {
		res = await ctx.fetchImpl(req.url, { ...init, signal: controller.signal });
	} catch (err) {
		return { observed: false, reason: "error", detail: err instanceof Error ? err.message : String(err) };
	} finally {
		if (timer) clearTimeout(timer);
	}

	// Honor 429 explicitly — a rate-limit is NOT a `blocked` verdict; back off.
	if (res.status === 429) return { observed: false, reason: "rate_limited" };

	let body = "";
	try {
		body = (await res.text()).slice(0, MAX_BODY_CHARS);
	} catch {
		body = "";
	}
	return { observed: true, status: res.status, body };
};

/** A seam executor that has no wired runner: every PoC is `not_replayable`. */
function unwired(kind: string): Executor {
	return async (): Promise<ExecOutcome> => ({
		observed: false,
		reason: "not_replayable",
		detail: `${kind} replay runner not wired into the oracle phase`,
	});
}

/** Default executor set: real HTTP replay; browser / OOB are not-yet-wired seams. */
export const DEFAULT_EXECUTORS: ExecutorSet = {
	http: httpExecutor,
	browser: unwired("browser"),
	oob: unwired("oob"),
};
