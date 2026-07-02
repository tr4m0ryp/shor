// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Egress control — default-deny outbound allowlist (LAUNCH-SPEC §5.6, §3.3;
 * ADR-022 / ADR-041; OWASP-APTS egress control).
 *
 * Two enforcement layers exist: per-tenant Direct VPC egress firewall at the
 * infra layer, and THIS in-code guard at the application boundary. The allowed
 * egress set is derived from the run's RoE in-scope hosts plus the GitHub App
 * clone hosts. Everything else is denied; the metadata endpoint and internal
 * ranges are hard-blocked even if an allow rule would otherwise match.
 *
 * `guardOutbound(url)` is the runtime check the dashboard side calls. The worker
 * keeps its own copy (`apps/worker/.../network-guard.ts`) reading the allowlist
 * from env, since the two packages must not import each other.
 */

import { getConfig } from '../config.js';
import type { ValidatedRoe } from './roe.js';
import { isBlockedHost, METADATA_IP } from './net.js';

/** GitHub clone/API hosts the App needs (ADR-041). */
export const GITHUB_APP_HOSTS: readonly string[] = ['github.com', 'api.github.com', 'codeload.github.com'] as const;

/** The derived, default-deny allowed-egress set for one run. */
export interface EgressAllowlist {
  /** Exact lowercase hostnames allowed (RoE hosts + GitHub App hosts). */
  readonly hosts: readonly string[];
  /** Suffixes for which subdomains are allowed (`.example.com`). */
  readonly suffixes: readonly string[];
}

export class EgressDeniedError extends Error {
  constructor(
    message: string,
    readonly url: string,
  ) {
    super(message);
    this.name = 'EgressDeniedError';
  }
}

/**
 * Derive the allowed-egress set from a validated RoE plus the GitHub App hosts.
 * RoE host rules with `includeSubdomains` become suffix entries; everything else
 * is an exact host. The result is the ONLY set `guardOutbound` will permit.
 */
export function deriveEgressAllowlist(roe: ValidatedRoe, extraHosts: readonly string[] = []): EgressAllowlist {
  const hosts = new Set<string>();
  const suffixes = new Set<string>();

  for (const rule of roe.allowedHosts) {
    const h = rule.host.trim().toLowerCase();
    if (!h) continue;
    hosts.add(h);
    if (rule.includeSubdomains === true) suffixes.add(`.${h}`);
  }
  for (const h of [...GITHUB_APP_HOSTS, ...extraHosts]) {
    const v = h.trim().toLowerCase();
    if (v) hosts.add(v);
  }

  return { hosts: [...hosts], suffixes: [...suffixes] };
}

/** Build the allowlist using the configured GitHub App hosts for this deploy. */
export function deriveEgressAllowlistFromConfig(roe: ValidatedRoe): EgressAllowlist {
  // Reading config keeps a single seam: a self-hosted GitHub Enterprise host
  // could be added to the extra-hosts set here without touching call sites. The
  // default GitHub.com clone hosts are always included by `deriveEgressAllowlist`.
  const { appId } = getConfig().github;
  const extra: string[] = appId ? [] : [];
  return deriveEgressAllowlist(roe, extra);
}

function hostAllowed(allowlist: EgressAllowlist, host: string): boolean {
  if (allowlist.hosts.includes(host)) return true;
  return allowlist.suffixes.some((s) => host.endsWith(s));
}

/**
 * Runtime egress check. Throws `EgressDeniedError` when `url` is malformed, uses
 * a non-http(s) scheme, targets the metadata endpoint / an internal range, or is
 * not on `allowlist`. Default-deny: an empty allowlist permits nothing.
 */
export function guardOutbound(url: string, allowlist: EgressAllowlist): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new EgressDeniedError(`malformed outbound URL "${url}"`, url);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new EgressDeniedError(`scheme "${parsed.protocol}" is not permitted for egress`, url);
  }

  const host = parsed.hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // Hard block: metadata + internal ranges, before any allowlist consideration.
  if (isBlockedHost(host)) {
    const why = host === METADATA_IP ? 'cloud metadata endpoint' : 'internal/loopback address';
    throw new EgressDeniedError(`egress to ${why} ("${host}") is blocked`, url);
  }

  if (!hostAllowed(allowlist, host)) {
    throw new EgressDeniedError(`egress to "${host}" is not on the allowlist (default-deny)`, url);
  }
}

/** Non-throwing egress predicate. */
export function isEgressAllowed(url: string, allowlist: EgressAllowlist): boolean {
  try {
    guardOutbound(url, allowlist);
    return true;
  } catch {
    return false;
  }
}
