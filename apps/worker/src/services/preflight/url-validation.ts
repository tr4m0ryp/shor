// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Target URL preflight validation.
 *
 * Performs DNS resolution and an HTTP HEAD probe so unreachable targets
 * fail fast. Detects loopback addresses inside the container and hints
 * at the `host.docker.internal` workaround. Clearnet-only.
 */

import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { ErrorCode } from "../../types/errors.js";
import { err, ok, type Result } from "../../types/result.js";
import { PentestError } from "../error-handling.js";

const TARGET_URL_TIMEOUT_MS = 10_000;

function isLoopbackAddress(address: string): boolean {
	return address === "127.0.0.1" || address === "::1" || address === "0.0.0.0";
}

/**
 * HTTP HEAD probe with TLS verification disabled — we check reachability, not
 * certificate validity.
 */
function httpProbe(url: string, timeoutMs: number): Promise<number> {
	return new Promise((resolve, reject) => {
		const parsed = new URL(url);
		const isHttps = parsed.protocol === "https:";
		const transport = isHttps ? https : http;

		const req = transport.request(
			url,
			{
				method: "HEAD",
				timeout: timeoutMs,
				...(isHttps && { rejectUnauthorized: false }),
			},
			(res) => {
				res.resume();
				resolve(res.statusCode ?? 0);
			},
		);

		req.on("timeout", () => {
			req.destroy();
			reject(new Error(`Connection timed out after ${timeoutMs}ms`));
		});
		req.on("error", reject);
		req.end();
	});
}

/** Check that the target URL is reachable from inside the container. */
export async function validateTargetUrl(
	targetUrl: string,
	logger: ActivityLogger,
): Promise<Result<void, PentestError>> {
	logger.info("Checking target URL reachability...", { targetUrl });

	// 1. Parse URL
	let parsed: URL;
	try {
		parsed = new URL(targetUrl);
	} catch {
		return err(
			new PentestError(
				`Invalid target URL: ${targetUrl}`,
				"config",
				false,
				{ targetUrl },
				ErrorCode.TARGET_UNREACHABLE,
			),
		);
	}

	// 2. DNS lookup — detect loopback addresses early for a better hint
	const hostname = parsed.hostname;
	let resolvedAddress: string | undefined;
	try {
		const result = await lookup(hostname);
		resolvedAddress = result.address;
	} catch {
		return err(
			new PentestError(
				`Target URL ${targetUrl} is not reachable. Verify the URL is correct and the site is up.`,
				"network",
				false,
				{ targetUrl, hostname },
				ErrorCode.TARGET_UNREACHABLE,
			),
		);
	}

	// 3. HTTP reachability check
	try {
		await httpProbe(targetUrl, TARGET_URL_TIMEOUT_MS);

		logger.info("Target URL OK");
		return ok(undefined);
	} catch (error) {
		const isLoopback = isLoopbackAddress(resolvedAddress);
		const detail = error instanceof Error ? error.message : String(error);

		if (isLoopback) {
			const suggestion = targetUrl.replace(hostname, "host.docker.internal");
			return err(
				new PentestError(
					`Target URL ${targetUrl} resolves to ${resolvedAddress} (loopback) and is not reachable. ` +
						`For local services, use host.docker.internal instead of ${hostname} (e.g., ${suggestion})`,
					"network",
					false,
					{ targetUrl, resolvedAddress, hostname },
					ErrorCode.TARGET_UNREACHABLE,
				),
			);
		}

		return err(
			new PentestError(
				`Target URL ${targetUrl} is not reachable: ${detail}`,
				"network",
				false,
				{ targetUrl, resolvedAddress },
				ErrorCode.TARGET_UNREACHABLE,
			),
		);
	}
}
