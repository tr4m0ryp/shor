// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Worker-side Rules of Engagement scope check (LAUNCH-SPEC §5.6, §3.3).
 *
 * The control plane authors + validates the RoE (`apps/web/.../guardrails/roe`)
 * and hands the worker the validated document via env (SHOR_ROE). The worker
 * only needs to ASK "is this URL in scope?" before each network action. This is
 * a self-contained copy of the scope predicate — the packages must not import
 * each other, and the RoE shape is the contract.
 */

export type RoeScheme = "http" | "https";

export interface RoeHostRule {
	host: string;
	includeSubdomains?: boolean;
	schemes?: RoeScheme[];
	pathPrefixes?: string[];
	ports?: number[];
}

export interface Roe {
	version: 1;
	targetUrl: string;
	allowedHosts: RoeHostRule[];
	deniedHosts?: string[];
}

export class RoeViolationError extends Error {
	constructor(
		message: string,
		readonly url: string,
	) {
		super(message);
		this.name = "RoeViolationError";
	}
}

const DEFAULT_PORT: Record<RoeScheme, number> = { http: 80, https: 443 };

function normalizeHost(host: string): string {
	return host.trim().toLowerCase().replace(/\.$/, "");
}

function hostMatches(rule: RoeHostRule, host: string): boolean {
	const ruleHost = normalizeHost(rule.host);
	if (host === ruleHost) return true;
	if (rule.includeSubdomains === true) return host.endsWith(`.${ruleHost}`);
	return false;
}

function schemeAllowed(rule: RoeHostRule, scheme: RoeScheme): boolean {
	const allowed = rule.schemes && rule.schemes.length > 0 ? rule.schemes : ["https"];
	return allowed.includes(scheme);
}

function pathAllowed(rule: RoeHostRule, path: string): boolean {
	const prefixes = rule.pathPrefixes ?? [];
	if (prefixes.length === 0) return true;
	return prefixes.some((p) => path === p || path.startsWith(p));
}

function portAllowed(rule: RoeHostRule, scheme: RoeScheme, port: number): boolean {
	const ports = rule.ports ?? [];
	if (ports.length === 0) return port === DEFAULT_PORT[scheme];
	return ports.includes(port);
}

/**
 * Assert a URL is in scope per the RoE. Throws `RoeViolationError` on any
 * violation. Call immediately before EVERY network action. Default-deny: an
 * empty `allowedHosts` authorizes nothing.
 */
export function assertInScope(roe: Roe, url: string): void {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new RoeViolationError(`malformed URL "${url}"`, url);
	}

	const scheme = parsed.protocol.replace(":", "");
	if (scheme !== "http" && scheme !== "https") {
		throw new RoeViolationError(`scheme "${scheme}" is never in scope`, url);
	}
	const host = normalizeHost(parsed.hostname);

	for (const denied of roe.deniedHosts ?? []) {
		const d = normalizeHost(denied);
		if (host === d || host.endsWith(`.${d}`)) {
			throw new RoeViolationError(`host "${host}" is on the RoE deny-list`, url);
		}
	}

	const port = parsed.port === "" ? DEFAULT_PORT[scheme] : Number.parseInt(parsed.port, 10);
	const path = parsed.pathname || "/";

	const matched = roe.allowedHosts.some(
		(rule) =>
			hostMatches(rule, host) &&
			schemeAllowed(rule, scheme) &&
			portAllowed(rule, scheme, port) &&
			pathAllowed(rule, path),
	);

	if (!matched) {
		throw new RoeViolationError(`"${host}${path}" (${scheme}:${port}) is out of scope`, url);
	}
}

/** Non-throwing scope predicate. */
export function isInScope(roe: Roe, url: string): boolean {
	try {
		assertInScope(roe, url);
		return true;
	} catch {
		return false;
	}
}
