// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Target-agnostic auth-provider contract (T9 — de-WordPress the oracle).
 *
 * Ali's oracle hard-coupled identity acquisition, whoami, and self-heal to
 * wp-json / admin-ajax rest-nonce / WP application-passwords. Our targets are
 * general web apps, so this interface hoists identity handling behind a provider
 * that works for session-cookie / bearer-JWT / OIDC / API-key auth — with the
 * WordPress specifics reimplemented (clean-room) INSIDE `WordPressAuthProvider`,
 * never in the generic core.
 *
 * ADR-050: an {@link AuthCandidate}'s header VALUES are secret — used to build a
 * request, NEVER logged or persisted. A {@link ProviderIdentity}'s principal
 * carries only non-secret label/role for logs; any runtime token (username) it
 * holds is in-memory-only for the echo assertion.
 */

import type { ActivityLogger } from '../../../types/activity-logger.js';

/** Which authentication mechanism a candidate uses. Non-secret. */
export type AuthCandidateKind =
  | 'app-password'
  | 'basic'
  | 'api-key'
  | 'bearer'
  | 'oidc-bearer'
  | 'cookie+csrf'
  | 'cookie';

/**
 * One ordered way to authenticate as an identity. `durability` ranks how well the
 * candidate survives session churn (HIGHER = more durable); a provider tries the
 * most-durable candidate first and `reauth` falls to the next. Header VALUES are
 * secret (ADR-050).
 */
export interface AuthCandidate {
  readonly kind: AuthCandidateKind;
  readonly durability: number;
  readonly headers: Readonly<Record<string, string>>;
}

/**
 * Non-secret principal an authenticated identity is expected to resolve to — the
 * expectation a whoami/identity-echo asserts before a replay is trusted.
 */
export interface ExpectedPrincipal {
  /** Directory label (e.g. 'primary', 'identity-member'). Non-secret. */
  readonly label: string;
  /** Role token, when known (non-secret). */
  readonly role?: string;
  /**
   * Runtime-only principal tokens (username / user-id / slug) the echo may assert
   * against. Held in-memory for the echo ONLY — never logged or persisted
   * (ADR-050). Absent on the directory-driven path (label/role only).
   */
  readonly runtimeTokens?: readonly string[];
}

/** A provider's view of one identity to replay under. */
export interface ProviderIdentity {
  readonly label: string;
  /** Always `true` here — the anonymous floor is an oracle construct, not an identity. */
  readonly authenticated: true;
  readonly principal: ExpectedPrincipal;
  /** Ordered auth candidates, most-durable-first (index 0 is preferred). */
  readonly candidates: readonly AuthCandidate[];
}

/** Where identity session state lives. Passed to {@link AuthProvider.acquireIdentities}. */
export interface AcquireContext {
  /** Deliverables dir; storage-state identity dirs resolve relative to it. */
  readonly deliverablesPath: string;
  readonly logger: ActivityLogger;
}

/** Transport a whoami echo needs. Mirrors the oracle ExecCtx but provider-owned. */
export interface EchoContext {
  readonly fetchImpl: typeof fetch;
  /** Network guard — MUST wrap every outbound request (default-deny egress). */
  readonly assertAllowed: (url: string) => void;
  /** Per-request timeout in ms; `<= 0` disables the abort timer. */
  readonly timeoutMs: number;
  readonly logger: ActivityLogger;
}

/**
 * whoami/identity-echo verdict. `confirmed` ⇒ the identity resolved to its
 * expected principal and a replay under it may be trusted. `inconclusive_infra` ⇒
 * the echo could not confirm it (no endpoint, transport error, or a MISMATCH — a
 * silent logout / wrong session). Per T9 a failed echo is inconclusive, NEVER a
 * `blocked` refutation.
 */
export type EchoStatus = 'confirmed' | 'inconclusive_infra';

/** Non-secret detail of why an echo landed where it did. */
export type EchoReason = 'matched' | 'mismatch' | 'no_endpoint' | 'error' | 'unreachable';

export interface EchoResult {
  readonly status: EchoStatus;
  readonly reason: EchoReason;
}

/**
 * Target-agnostic authentication provider (T9). Sits behind identity acquisition,
 * auth-candidate ordering, whoami/identity-echo, and self-heal. Every method
 * fail-opens: acquisition never throws, a failed echo is inconclusive.
 */
export interface AuthProvider {
  readonly name: string;
  /**
   * Discover the ordered AUTHENTICATED identity set (the anonymous floor is added
   * by the oracle, not here). The privileged primary baseline is excluded — it is
   * the PoC's own identity, not a differential.
   */
  acquireIdentities(ctx: AcquireContext): ProviderIdentity[];
  /** Ordered auth candidates for one identity, most-durable-first. */
  authCandidates(identity: ProviderIdentity): readonly AuthCandidate[];
  /**
   * Assert we are really firing as `identity`'s expected principal before a replay
   * is trusted. Runs for EVERY authenticated identity (Ali's cookie-only gap). A
   * failed or mismatched echo → `inconclusive_infra`, never `blocked`.
   */
  whoamiEcho(identity: ProviderIdentity, candidate: AuthCandidate, ctx: EchoContext): Promise<EchoResult>;
  /**
   * Self-heal: advance from a spent candidate to the next (less-durable) one;
   * `undefined` when the ordered candidate list is exhausted.
   */
  reauth(identity: ProviderIdentity, spent: AuthCandidate): AuthCandidate | undefined;
}

/** Auth scheme a target uses, as detected from RoE / recon metadata. */
export type AuthScheme = 'cookie' | 'bearer' | 'oidc' | 'api-key';

/**
 * Target metadata that drives {@link selectAuthProvider}. All fields optional so an
 * unknown target defaults cleanly to the generic session-cookie provider (today's
 * behavior). `platform === 'wordpress'` is the ONLY thing that selects the WP
 * provider — no WP assumption leaks into the default path.
 */
export interface TargetAuthMeta {
  /** Detected platform (recon); 'wordpress' selects `WordPressAuthProvider`. */
  readonly platform?: string;
  /** Primary auth scheme hint (recon). Absent ⇒ 'cookie'. */
  readonly scheme?: AuthScheme;
  /** Absolute whoami/identity-echo endpoint, when known (generic providers). */
  readonly whoamiUrl?: string;
  /** Target origin — providers with a conventional echo path build it from this. */
  readonly origin?: string;
  /** Header carrying an API key (default 'X-API-Key'). */
  readonly apiKeyHeader?: string;
  /** Explicit override seam (env flag SHOR_AUTH_PROVIDER); wins over detection. */
  readonly force?: AuthScheme | 'wordpress';
}
