// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Session-cookie provider — the generic DEFAULT for cookie-authenticated web apps.
 *
 * Acquisition reads each non-primary identity's Playwright storage-state cookies
 * and offers a single `cookie` candidate — exactly today's differential behavior,
 * so a stock scan is byte-identical. whoami/identity-echo hits a configured
 * endpoint (there is no universal cookie whoami convention); absent an endpoint the
 * echo is `inconclusive_infra`, never a refutation.
 */

import {
  cookieCandidate,
  cookieHeaderFrom,
  discoverIdentityStates,
  orderCandidates,
} from './candidates.js';
import { networkEcho } from './whoami.js';
import type {
  AcquireContext,
  AuthCandidate,
  AuthProvider,
  EchoContext,
  EchoResult,
  ProviderIdentity,
} from './types.js';

/** Optional wiring for the generic providers (no built-in echo convention). */
export interface GenericProviderConfig {
  /** Absolute whoami endpoint asserted against the identity's principal. */
  readonly whoamiUrl?: string;
}

export class SessionCookieAuthProvider implements AuthProvider {
  readonly name: string = 'session-cookie';
  protected readonly config: GenericProviderConfig;

  constructor(config: GenericProviderConfig = {}) {
    this.config = config;
  }

  acquireIdentities(ctx: AcquireContext): ProviderIdentity[] {
    const out: ProviderIdentity[] = [];
    for (const { label, state } of discoverIdentityStates(ctx.deliverablesPath)) {
      const cookie = cookieHeaderFrom(state);
      if (cookie === '') continue;
      out.push({
        label,
        authenticated: true,
        principal: { label },
        candidates: [cookieCandidate(cookie)],
      });
    }
    return out;
  }

  authCandidates(identity: ProviderIdentity): readonly AuthCandidate[] {
    return orderCandidates(identity.candidates);
  }

  async whoamiEcho(
    identity: ProviderIdentity,
    candidate: AuthCandidate,
    ctx: EchoContext,
  ): Promise<EchoResult> {
    return networkEcho(this.config.whoamiUrl, candidate.headers, identity.principal, ctx);
  }

  reauth(identity: ProviderIdentity, spent: AuthCandidate): AuthCandidate | undefined {
    const ordered = this.authCandidates(identity);
    const idx = ordered.indexOf(spent);
    return idx < 0 ? ordered[0] : ordered[idx + 1];
  }
}
