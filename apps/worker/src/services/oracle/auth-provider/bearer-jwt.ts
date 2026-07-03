// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Bearer-JWT provider — token-authenticated SPAs / APIs.
 *
 * Acquisition scans each non-primary identity's storage-state `localStorage` for a
 * value that decodes as a JWT and offers it as a `bearer` candidate. Its winning
 * property: whoami/identity-echo needs NO round-trip — the JWT's own claims name
 * the principal (`sub`/`preferred_username`/…), so `jwtClaimEcho` asserts identity
 * locally and only falls back to a `networkEcho` when the claim is inconclusive.
 */

import { bearerCandidate, bearerTokenOf, discoverIdentityStates, orderCandidates } from './candidates.js';
import type { GenericProviderConfig } from './session-cookie.js';
import { decodeJwtClaims, jwtClaimEcho, networkEcho } from './whoami.js';
import type {
  AcquireContext,
  AuthCandidate,
  AuthProvider,
  EchoContext,
  EchoResult,
  ProviderIdentity,
} from './types.js';

/** First localStorage value that decodes as a JWT, else `undefined`. */
function findJwt(items: { name: string; value: string }[]): string | undefined {
  for (const { value } of items) {
    if (typeof value === 'string' && value.split('.').length === 3 && decodeJwtClaims(value)) return value;
  }
  return undefined;
}

export class BearerJwtAuthProvider implements AuthProvider {
  readonly name: string = 'bearer-jwt';
  protected readonly config: GenericProviderConfig;

  constructor(config: GenericProviderConfig = {}) {
    this.config = config;
  }

  acquireIdentities(ctx: AcquireContext): ProviderIdentity[] {
    const out: ProviderIdentity[] = [];
    for (const { label, state } of discoverIdentityStates(ctx.deliverablesPath)) {
      const token = state.origins.map((o) => findJwt(o.localStorage)).find((t): t is string => t !== undefined);
      if (!token) continue;
      out.push({
        label,
        authenticated: true,
        principal: { label },
        candidates: [this.candidateFor(token)],
      });
    }
    return out;
  }

  /** Overridable so OIDC can tag its own `oidc-bearer` kind while reusing acquisition. */
  protected candidateFor(token: string): AuthCandidate {
    return bearerCandidate(token);
  }

  authCandidates(identity: ProviderIdentity): readonly AuthCandidate[] {
    return orderCandidates(identity.candidates);
  }

  async whoamiEcho(
    identity: ProviderIdentity,
    candidate: AuthCandidate,
    ctx: EchoContext,
  ): Promise<EchoResult> {
    const token = bearerTokenOf(candidate.headers);
    if (token) {
      const local = jwtClaimEcho(token, identity.principal);
      if (local.status === 'confirmed') return local;
    }
    return networkEcho(this.config.whoamiUrl, candidate.headers, identity.principal, ctx);
  }

  reauth(identity: ProviderIdentity, spent: AuthCandidate): AuthCandidate | undefined {
    const ordered = this.authCandidates(identity);
    const idx = ordered.indexOf(spent);
    return idx < 0 ? ordered[0] : ordered[idx + 1];
  }
}
