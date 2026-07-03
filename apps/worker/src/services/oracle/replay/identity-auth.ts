// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Identity → replay-auth bridge for the differential oracle (T1/T9).
 *
 * This is the seam between the target-agnostic {@link AuthProvider} and the
 * executable-replay runner. It acquires each scan identity through the selected
 * provider (default: generic session-cookie) and flattens it to the runner's
 * {@link ReplayIdentity} shape, using the identity's MOST-DURABLE auth candidate.
 * The PRIMARY (privileged) identity is excluded by the provider — it is the PoC's
 * own baseline, not a differential. An anonymous (no-auth) floor is ALWAYS
 * prepended here (an oracle construct, not an identity a provider owns).
 *
 * De-WordPress (T9): the WordPress-specific whoami / candidate-ordering now lives
 * inside `WordPressAuthProvider`; this bridge is provider-agnostic. Running the
 * per-identity whoami/identity-echo before a replay is trusted is the integration
 * step OWNED BY 008 — see {@link acquireProviderIdentities}, which exposes the
 * provider + identities so 008 can echo without this file touching the runner.
 *
 * ADR-050: candidate header VALUES are read only to construct the replay request;
 * they are NEVER logged or surfaced. Fail-open everywhere: a missing/malformed
 * state file contributes no identity, never throws.
 */

import type { ActivityLogger } from '../../../types/activity-logger.js';
import { selectAuthProvider } from '../auth-provider/index.js';
import type { AuthProvider, ProviderIdentity, TargetAuthMeta } from '../auth-provider/index.js';

/** A lower-privilege identity to replay an authz PoC under. */
export interface ReplayIdentity {
  label: string;
  /** false ⇒ the anonymous (no-auth) floor; true ⇒ a real authenticated identity. */
  authenticated: boolean;
  headers: Record<string, string>;
}

/** Anonymous floor: strip all auth (the executor removes the PoC's captured auth). */
const ANONYMOUS: ReplayIdentity = { label: 'anonymous', authenticated: false, headers: {} };

/**
 * Acquire the authenticated identities through the selected provider, returning
 * both the provider and its identities. This is the T9-clean seam 008 consumes to
 * run `provider.whoamiEcho(...)` for EVERY authenticated identity before trusting a
 * differential replay — kept here so the runner (`replay/index.ts`, owned by 008)
 * need not change to gain the provider abstraction.
 */
export function acquireProviderIdentities(
  deliverablesPath: string,
  logger: ActivityLogger,
  meta: TargetAuthMeta = {},
): { provider: AuthProvider; identities: ProviderIdentity[] } {
  const provider = selectAuthProvider(meta);
  let identities: ProviderIdentity[] = [];
  try {
    identities = provider.acquireIdentities({ deliverablesPath, logger });
  } catch (err) {
    // Fail-open: acquisition problems degrade coverage, never abort the phase.
    logger.warn('Oracle auth-provider acquisition failed; no authenticated identities', {
      provider: provider.name,
      error: err instanceof Error ? err.message : String(err),
    });
  }
  return { provider, identities };
}

/**
 * Load the differential replay identities: anonymous (always) + every authenticated
 * identity the provider acquired, each flattened to its most-durable auth candidate.
 * Directory-driven and provider-selected; the primary identity is excluded upstream.
 */
export function loadDifferentialIdentities(
  deliverablesPath: string,
  logger: ActivityLogger,
  meta: TargetAuthMeta = {},
): ReplayIdentity[] {
  const { provider, identities } = acquireProviderIdentities(deliverablesPath, logger, meta);
  const out: ReplayIdentity[] = [ANONYMOUS];
  for (const identity of identities) {
    const best = provider.authCandidates(identity)[0];
    if (!best) continue;
    out.push({ label: identity.label, authenticated: true, headers: { ...best.headers } });
  }
  // Log labels only — never the cookie/token values (ADR-050).
  logger.info('Oracle differential: loaded lower-privilege identities', {
    provider: provider.name,
    count: out.length,
    labels: out.map((i) => i.label),
  });
  return out;
}
