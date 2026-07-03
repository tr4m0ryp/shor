// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * API-key provider — header-key authenticated APIs.
 *
 * Unlike cookie/bearer, an API key never lives in a browser storage-state, so
 * acquisition is CONFIG-driven: the caller (008 / RoE) supplies the per-identity
 * keys. ADR-050: a key value is held in-memory only to build the request header —
 * it is never logged, and only the non-secret label/role/principal tokens reach
 * logs. whoami/identity-echo hits a configured endpoint (a key carries no decodable
 * principal); absent one, the echo is `inconclusive_infra`.
 */

import { apiKeyCandidate, orderCandidates } from './candidates.js';
import { networkEcho } from './whoami.js';
import type {
  AcquireContext,
  AuthCandidate,
  AuthProvider,
  EchoContext,
  EchoResult,
  ProviderIdentity,
} from './types.js';

/** One config-supplied API-key identity. `key` is a runtime secret (ADR-050). */
export interface ApiKeyIdentityConfig {
  readonly label: string;
  readonly role?: string;
  readonly key: string;
  /** Non-secret principal tokens the echo asserts (e.g. a service-account id). */
  readonly principalTokens?: readonly string[];
}

export interface ApiKeyProviderConfig {
  /** Header carrying the key (default 'X-API-Key'). */
  readonly apiKeyHeader?: string;
  readonly whoamiUrl?: string;
  /** Config-supplied identities (acquisition source — no storage-state heuristic). */
  readonly identities?: readonly ApiKeyIdentityConfig[];
}

const DEFAULT_API_KEY_HEADER = 'X-API-Key';

export class ApiKeyAuthProvider implements AuthProvider {
  readonly name = 'api-key';
  private readonly header: string;
  private readonly whoamiUrl: string | undefined;
  private readonly identities: readonly ApiKeyIdentityConfig[];

  constructor(config: ApiKeyProviderConfig = {}) {
    this.header = config.apiKeyHeader ?? DEFAULT_API_KEY_HEADER;
    this.whoamiUrl = config.whoamiUrl;
    this.identities = config.identities ?? [];
  }

  acquireIdentities(_ctx: AcquireContext): ProviderIdentity[] {
    return this.identities.map((id) => ({
      label: id.label,
      authenticated: true,
      principal: {
        label: id.label,
        ...(id.role !== undefined && { role: id.role }),
        ...(id.principalTokens !== undefined && { runtimeTokens: id.principalTokens }),
      },
      candidates: [apiKeyCandidate(this.header, id.key)],
    }));
  }

  authCandidates(identity: ProviderIdentity): readonly AuthCandidate[] {
    return orderCandidates(identity.candidates);
  }

  async whoamiEcho(
    identity: ProviderIdentity,
    candidate: AuthCandidate,
    ctx: EchoContext,
  ): Promise<EchoResult> {
    return networkEcho(this.whoamiUrl, candidate.headers, identity.principal, ctx);
  }

  reauth(identity: ProviderIdentity, spent: AuthCandidate): AuthCandidate | undefined {
    const ordered = this.authCandidates(identity);
    const idx = ordered.indexOf(spent);
    return idx < 0 ? ordered[0] : ordered[idx + 1];
  }
}
