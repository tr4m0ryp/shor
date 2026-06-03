// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Worker network guard (LAUNCH-SPEC §5.6, §3.3) — the single chokepoint the
 * engine calls before ANY outbound tool/network action.
 *
 * `assertNetworkAllowed(url)` enforces, in order:
 *   1. Hard block — metadata endpoint + internal/loopback ranges (always).
 *   2. RoE scope — the URL must be in the run's Rules of Engagement.
 *   3. Egress allowlist — the host must be on the derived allowed-egress set
 *      (RoE hosts + GitHub App hosts). Default-deny.
 *
 * Inputs are read from the Cloud Run Job environment (the dashboard sets them on
 * the per-scan Job): the validated RoE JSON in SHOR_ROE, and an optional
 * whitespace/comma-separated host allowlist in SHOR_EGRESS_ALLOWLIST (when
 * absent it is derived from the RoE plus the GitHub App hosts). Parsing is
 * memoized; this module performs no I/O.
 */

import { isBlockedHost, METADATA_IP } from "./net.js";
import { assertInScope, type Roe } from "./roe.js";

/** GitHub clone/API hosts the App needs (kept in sync with the web copy). */
export const GITHUB_APP_HOSTS: readonly string[] = [
	"github.com",
	"api.github.com",
	"codeload.github.com",
];

export class NetworkGuardError extends Error {
	constructor(
		message: string,
		readonly url: string,
	) {
		super(message);
		this.name = "NetworkGuardError";
	}
}

interface GuardContext {
	roe: Roe | null;
	allowHosts: Set<string>;
	allowSuffixes: string[];
	/** Infra egress hosts (GitHub App) — allowed by egress without RoE scope. */
	infraHosts: Set<string>;
}

let cached: GuardContext | undefined;

function parseRoe(): Roe | null {
	const raw = process.env.SHOR_ROE;
	if (!raw || raw.trim() === "") return null;
	try {
		const parsed = JSON.parse(raw) as Roe;
		if (!Array.isArray(parsed.allowedHosts)) return null;
		return parsed;
	} catch {
		return null;
	}
}

function deriveAllowlist(roe: Roe | null): { hosts: Set<string>; suffixes: string[] } {
	const hosts = new Set<string>();
	const suffixes: string[] = [];

	// Explicit env override wins; otherwise derive from the RoE.
	const explicit = process.env.SHOR_EGRESS_ALLOWLIST;
	if (explicit && explicit.trim() !== "") {
		for (const h of explicit.split(/[\s,]+/)) {
			const v = h.trim().toLowerCase();
			if (v) hosts.add(v);
		}
	} else if (roe) {
		for (const rule of roe.allowedHosts) {
			const v = rule.host.trim().toLowerCase();
			if (!v) continue;
			hosts.add(v);
			if (rule.includeSubdomains === true) suffixes.push(`.${v}`);
		}
	}

	for (const h of GITHUB_APP_HOSTS) hosts.add(h);
	return { hosts, suffixes };
}

function context(): GuardContext {
	if (cached) return cached;
	const roe = parseRoe();
	const { hosts, suffixes } = deriveAllowlist(roe);
	cached = {
		roe,
		allowHosts: hosts,
		allowSuffixes: suffixes,
		infraHosts: new Set(GITHUB_APP_HOSTS),
	};
	return cached;
}

/** Test/runtime hook: re-read SHOR_ROE / SHOR_EGRESS_ALLOWLIST on next call. */
export function resetNetworkGuard(): void {
	cached = undefined;
}

function hostAllowed(ctx: GuardContext, host: string): boolean {
	if (ctx.allowHosts.has(host)) return true;
	return ctx.allowSuffixes.some((s) => host.endsWith(s));
}

/**
 * Assert an outbound URL is permitted. Throws `NetworkGuardError` (or the
 * underlying `RoeViolationError`) on any violation. Default-deny end to end.
 */
export function assertNetworkAllowed(url: string): void {
	const ctx = context();

	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new NetworkGuardError(`malformed outbound URL "${url}"`, url);
	}

	if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
		throw new NetworkGuardError(`scheme "${parsed.protocol}" is not permitted`, url);
	}

	const host = parsed.hostname.trim().toLowerCase().replace(/^\[|\]$/g, "");

	// 1. Hard block (metadata + internal ranges) regardless of allowlist.
	if (isBlockedHost(host)) {
		const why = host === METADATA_IP ? "cloud metadata endpoint" : "internal/loopback address";
		throw new NetworkGuardError(`egress to ${why} ("${host}") is blocked`, url);
	}

	// Infra egress (GitHub App clone/API hosts) is permitted without an RoE
	// scope match — the RoE governs the SCAN TARGET, not the platform's own
	// clone egress (ADR-041). It still must be on the egress allowlist.
	const isInfra = ctx.infraHosts.has(host);

	// 2. RoE scope (when an RoE is configured), except for infra egress hosts.
	if (ctx.roe && !isInfra) assertInScope(ctx.roe, url);

	// 3. Egress allowlist (default-deny).
	if (!hostAllowed(ctx, host)) {
		throw new NetworkGuardError(`egress to "${host}" is not on the allowlist (default-deny)`, url);
	}
}

/** Non-throwing variant for call sites that prefer a boolean. */
export function isNetworkAllowed(url: string): boolean {
	try {
		assertNetworkAllowed(url);
		return true;
	} catch {
		return false;
	}
}
