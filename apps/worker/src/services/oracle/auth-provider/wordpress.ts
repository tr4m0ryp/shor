// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * WordPress provider — where ALL WP specifics live (clean-room; not Ali's fork).
 *
 * Selected ONLY when recon reports `platform === 'wordpress'`; the generic core
 * never assumes WP. It preserves the prior cookie behavior and reintroduces the
 * WP-flavored durability order Ali relied on: an application-password (HTTP Basic)
 * outranks a cookie+REST-nonce, which outranks a bare cookie. On the directory-only
 * path (no configured WP credentials) it degrades to the SAME cookie-only candidate
 * the session-cookie provider produces — so no existing scan regresses. whoami hits
 * the WP convention `/wp-json/wp/v2/users/me?context=edit`.
 */

import { basicCandidate, cookieCandidate, cookieCsrfCandidate, cookieHeaderFrom, discoverIdentityStates } from './candidates.js';
import { SessionCookieAuthProvider } from './session-cookie.js';
import { networkEcho } from './whoami.js';
import type { AcquireContext, AuthCandidate, EchoContext, EchoResult, ProviderIdentity } from './types.js';

/** Header carrying the WP REST nonce paired with a logged-in cookie. */
const WP_NONCE_HEADER = 'X-WP-Nonce';
/** WP convention: the current-user endpoint whose body names the principal. */
const WP_WHOAMI_PATH = '/wp-json/wp/v2/users/me?context=edit';

/** Config-driven WP credentials for one identity. All values runtime secrets (ADR-050). */
export interface WpIdentityAuth {
  /** base64(user:application_password) for the HTTP Basic app-password candidate. */
  readonly appPasswordBasic?: string;
  /** REST nonce value paired with the session cookie (`X-WP-Nonce`). */
  readonly restNonce?: string;
  /** Non-secret principal tokens (user slug / login) the echo asserts. */
  readonly principalTokens?: readonly string[];
}

export interface WordPressProviderConfig {
  /** Explicit whoami endpoint override; else built from {@link origin}. */
  readonly whoamiUrl?: string;
  /** Target origin used to build the `wp-json/.../users/me` echo endpoint. */
  readonly origin?: string;
  /** Per-identity WP credential extras, keyed by directory label. */
  readonly identityAuth?: Readonly<Record<string, WpIdentityAuth>>;
}

export class WordPressAuthProvider extends SessionCookieAuthProvider {
  override readonly name = 'wordpress';
  private readonly wp: WordPressProviderConfig;

  constructor(config: WordPressProviderConfig = {}) {
    super(config.whoamiUrl !== undefined ? { whoamiUrl: config.whoamiUrl } : {});
    this.wp = config;
  }

  override acquireIdentities(ctx: AcquireContext): ProviderIdentity[] {
    const out: ProviderIdentity[] = [];
    for (const { label, state } of discoverIdentityStates(ctx.deliverablesPath)) {
      const cookie = cookieHeaderFrom(state);
      const extra = this.wp.identityAuth?.[label];
      const candidates = this.candidatesFor(cookie, extra);
      if (candidates.length === 0) continue;
      out.push({
        label,
        authenticated: true,
        principal: {
          label,
          ...(extra?.principalTokens !== undefined && { runtimeTokens: extra.principalTokens }),
        },
        candidates,
      });
    }
    return out;
  }

  /** WP candidate list (unordered — `authCandidates` sorts by durability). */
  private candidatesFor(cookie: string, extra: WpIdentityAuth | undefined): AuthCandidate[] {
    const candidates: AuthCandidate[] = [];
    if (extra?.appPasswordBasic) candidates.push(basicCandidate(extra.appPasswordBasic, 'app-password'));
    if (extra?.restNonce && cookie !== '') {
      candidates.push(cookieCsrfCandidate(cookie, WP_NONCE_HEADER, extra.restNonce));
    }
    if (cookie !== '') candidates.push(cookieCandidate(cookie));
    return candidates;
  }

  private echoEndpoint(): string | undefined {
    if (this.wp.whoamiUrl) return this.wp.whoamiUrl;
    if (!this.wp.origin) return undefined;
    return `${this.wp.origin.replace(/\/$/, '')}${WP_WHOAMI_PATH}`;
  }

  override async whoamiEcho(
    identity: ProviderIdentity,
    candidate: AuthCandidate,
    ctx: EchoContext,
  ): Promise<EchoResult> {
    return networkEcho(this.echoEndpoint(), candidate.headers, identity.principal, ctx);
  }
}
