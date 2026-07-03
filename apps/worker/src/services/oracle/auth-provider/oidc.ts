// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * OIDC provider — a THIN STUB with a clear seam (T9).
 *
 * OIDC identities present as bearer tokens once logged in, so acquisition + echo
 * reuse {@link BearerJwtAuthProvider} (the id/access token is a JWT whose claims
 * name the principal). What OIDC adds beyond bearer is the token LIFECYCLE — an
 * auth-code+PKCE / refresh-token grant against a discovery endpoint. That exchange
 * is intentionally left as a documented seam ({@link OidcAuthProvider.tokenExchange})
 * for a later session; until it is wired, `reauth` degrades to the ordered
 * candidate walk (identical to bearer), never fabricating a token.
 */

import { oidcBearerCandidate } from './candidates.js';
import { BearerJwtAuthProvider } from './bearer-jwt.js';
import type { GenericProviderConfig } from './session-cookie.js';
import type { AuthCandidate } from './types.js';

/** Discovery/token-endpoint wiring for the OIDC grant (all optional until wired). */
export interface OidcProviderConfig extends GenericProviderConfig {
  /** OIDC issuer / `.well-known/openid-configuration` base, when known. */
  readonly issuer?: string;
  /** Token endpoint for the refresh / auth-code grant (from discovery). */
  readonly tokenEndpoint?: string;
}

export class OidcAuthProvider extends BearerJwtAuthProvider {
  override readonly name = 'oidc';
  protected readonly oidc: OidcProviderConfig;

  constructor(config: OidcProviderConfig = {}) {
    super(config);
    this.oidc = config;
  }

  protected override candidateFor(token: string): AuthCandidate {
    return oidcBearerCandidate(token);
  }

  /**
   * SEAM (not yet wired): exchange a refresh token / auth code for a fresh access
   * token at {@link OidcProviderConfig.tokenEndpoint}. A later session implements
   * the PKCE / refresh-token grant here; today it returns `undefined` so callers
   * fall back to the ordered candidate walk instead of an expired token.
   */
  async tokenExchange(): Promise<string | undefined> {
    // The token endpoint (from discovery) is where the grant WOULD be exchanged.
    // Until that is wired, refuse rather than fabricate: return no fresh token.
    void this.oidc.tokenEndpoint;
    return undefined;
  }
}
