// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Auth-provider module root (T9): public surface + the target-metadata selector.
 *
 * `selectAuthProvider` maps RoE / recon metadata to a concrete provider. The
 * default — an unknown target with no metadata — is the generic session-cookie
 * provider, which reproduces today's differential-auth behavior exactly, so a
 * stock scan is unchanged. The WordPress provider is chosen ONLY for a target
 * recon flagged `platform === 'wordpress'`.
 */

import { ApiKeyAuthProvider } from './api-key.js';
import { BearerJwtAuthProvider } from './bearer-jwt.js';
import { OidcAuthProvider } from './oidc.js';
import { SessionCookieAuthProvider } from './session-cookie.js';
import { WordPressAuthProvider } from './wordpress.js';
import type { AuthProvider, AuthScheme, TargetAuthMeta } from './types.js';

/** Env override seam (flag-gated, default OFF). Pins the provider when set. */
const AUTH_PROVIDER_ENV = 'SHOR_AUTH_PROVIDER';
const FORCE_VALUES: ReadonlySet<string> = new Set<AuthScheme | 'wordpress'>([
  'cookie',
  'bearer',
  'oidc',
  'api-key',
  'wordpress',
]);

function envForce(): AuthScheme | 'wordpress' | undefined {
  const raw = process.env[AUTH_PROVIDER_ENV]?.trim().toLowerCase();
  return raw && FORCE_VALUES.has(raw) ? (raw as AuthScheme | 'wordpress') : undefined;
}

/** Resolve the provider choice from an explicit force, the env seam, then detection. */
function resolveChoice(meta: TargetAuthMeta): AuthScheme | 'wordpress' {
  const forced = meta.force ?? envForce();
  if (forced) return forced;
  if (meta.platform?.trim().toLowerCase() === 'wordpress') return 'wordpress';
  return meta.scheme ?? 'cookie';
}

/** Build the concrete {@link AuthProvider} for a target. */
export function selectAuthProvider(meta: TargetAuthMeta = {}): AuthProvider {
  const generic = {
    ...(meta.whoamiUrl !== undefined && { whoamiUrl: meta.whoamiUrl }),
  };
  switch (resolveChoice(meta)) {
    case 'wordpress':
      return new WordPressAuthProvider({
        ...(meta.whoamiUrl !== undefined && { whoamiUrl: meta.whoamiUrl }),
        ...(meta.origin !== undefined && { origin: meta.origin }),
      });
    case 'bearer':
      return new BearerJwtAuthProvider(generic);
    case 'oidc':
      return new OidcAuthProvider(generic);
    case 'api-key':
      return new ApiKeyAuthProvider({
        ...(meta.whoamiUrl !== undefined && { whoamiUrl: meta.whoamiUrl }),
        ...(meta.apiKeyHeader !== undefined && { apiKeyHeader: meta.apiKeyHeader }),
      });
    default:
      return new SessionCookieAuthProvider(generic);
  }
}

export { ApiKeyAuthProvider } from './api-key.js';
export type { ApiKeyIdentityConfig, ApiKeyProviderConfig } from './api-key.js';
export { BearerJwtAuthProvider } from './bearer-jwt.js';
export { OidcAuthProvider } from './oidc.js';
export type { OidcProviderConfig } from './oidc.js';
export { SessionCookieAuthProvider } from './session-cookie.js';
export type { GenericProviderConfig } from './session-cookie.js';
export { WordPressAuthProvider } from './wordpress.js';
export type { WordPressProviderConfig, WpIdentityAuth } from './wordpress.js';
export {
  networkEcho,
  jwtClaimEcho,
  decodeJwtClaims,
  principalHints,
} from './whoami.js';
export type {
  AcquireContext,
  AuthCandidate,
  AuthCandidateKind,
  AuthProvider,
  AuthScheme,
  EchoContext,
  EchoReason,
  EchoResult,
  EchoStatus,
  ExpectedPrincipal,
  ProviderIdentity,
  TargetAuthMeta,
} from './types.js';
