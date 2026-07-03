// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-kind replay executors.
 *
 * `httpExecutor` is the in-process deterministic path: every outbound request is
 * wrapped by the network guard FIRST (default-deny egress, metadata/internal
 * blocked, RoE scope) and only then issued via the worker's `fetch`.
 *
 * The OOB executor is wired to the self-hosted-interactsh path (006): the default
 * set binds it to NO listener, so — exactly like the old unwired seam — every OOB
 * PoC is `not_replayable` until a live listener is injected. `buildExecutorSet`
 * lets the oracle phase (008) inject a live {@link OobListener} without touching
 * the runner or the read-only gate. The browser executor remains an unwired seam.
 */

import { createOobExecutor } from "./oob/index.js";
import type { OobListener } from "./oob/types.js";
import type { ExecOutcome, Executor, ExecutorSet } from "./types.js";

/** Cap the body we read so a huge response cannot exhaust memory. */
const MAX_BODY_CHARS = 64 * 1024;

/** Auth-bearing request headers replaced wholesale during a differential replay. */
const AUTH_HEADERS: ReadonlySet<string> = new Set(["authorization", "cookie"]);

/**
 * Resolve the headers for a replay. Baseline (no identity) ⇒ the PoC's own headers
 * unchanged. Differential (identity present) ⇒ STRIP the PoC's captured auth and
 * apply the identity's auth instead, so an anonymous identity (empty headers) truly
 * fires unauthenticated and a low-privilege identity fires as itself, not as the
 * privileged user the PoC was captured under.
 */
function resolveHeaders(
	pocHeaders: Record<string, string> | undefined,
	identityHeaders: Record<string, string> | undefined,
): Record<string, string> | undefined {
	if (!identityHeaders) return pocHeaders;
	const stripped: Record<string, string> = {};
	for (const [k, v] of Object.entries(pocHeaders ?? {})) {
		if (!AUTH_HEADERS.has(k.toLowerCase())) stripped[k] = v;
	}
	const merged = { ...stripped, ...identityHeaders };
	return Object.keys(merged).length > 0 ? merged : undefined;
}

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
	const headers = resolveHeaders(req.headers, ctx.currentIdentity?.headers);
	const init: RequestInit = {
		method,
		...(headers && { headers }),
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

/**
 * Build the executor set, binding the OOB executor (006) to `oobListener`. With no
 * listener (the default) the OOB path degrades to `not_replayable` — BYTE-identical
 * to the old unwired seam, so a stock scan is unchanged. Passing a live listener
 * (008, gated by `SHOR_OOB`) turns on real witnessed-callback proof.
 */
export function buildExecutorSet(oobListener?: OobListener): ExecutorSet {
	return {
		http: httpExecutor,
		browser: unwired("browser"),
		oob: createOobExecutor(oobListener),
	};
}

/** Default executor set: real HTTP replay; OOB via 006 (no listener ⇒ inconclusive). */
export const DEFAULT_EXECUTORS: ExecutorSet = buildExecutorSet();
