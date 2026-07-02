// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Google Cloud Identity Platform ID-token verification (ADR-016 / ADR-042 / ADR-043).
 *
 * Identity Platform (Firebase Auth) issues ~1h ID-token JWTs signed by the
 * `securetoken@system.gserviceaccount.com` service account. We verify them
 * server-side, then the dashboard mints its own HTTP-only session cookie
 * (ADR-043). The verified principal carries `{uid, tenantId, role, email}`:
 *   - `tenantId` comes from `firebase.tenant` (one IdP tenant per org).
 *   - `role` comes from a custom claim (`role`), one of owner|admin|member|viewer.
 *
 * Lazy: the verifier (an `OAuth2Client` used purely for its cert-fetch + JWT
 * verify helpers) is constructed on first use, never at import time, so
 * `tsc`/`build` need no live GCP credentials or network.
 */

import type { OAuth2Client } from 'google-auth-library';
import { getConfig } from '../config.js';
import type { UserRole } from '../domain/types.js';
import { USER_ROLES } from '../domain/types.js';

/** Verified caller identity extracted from an Identity Platform ID token. */
export interface VerifiedPrincipal {
  readonly uid: string;
  readonly tenantId: string;
  readonly role: UserRole;
  readonly email: string;
}

export class TokenVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenVerificationError';
  }
}

let verifier: OAuth2Client | undefined;

async function getVerifier(): Promise<OAuth2Client> {
  if (!verifier) {
    const mod = await import('google-auth-library');
    verifier = new mod.OAuth2Client();
  }
  return verifier;
}

/** Identity Platform issuer is `https://securetoken.google.com/<projectId>`. */
function issuer(projectId: string): string {
  return `https://securetoken.google.com/${projectId}`;
}

/**
 * Verify a Identity Platform / Firebase ID token and return the principal.
 *
 * Validates signature against Google's secure-token x509 certs, plus
 * `aud === projectId` and `iss === https://securetoken.google.com/<projectId>`.
 * Throws `TokenVerificationError` on any failure.
 */
export async function verifyIdToken(idToken: string): Promise<VerifiedPrincipal> {
  const { identity } = getConfig();
  const projectId = identity.projectId;
  if (!projectId) {
    throw new TokenVerificationError('IDENTITY_PLATFORM_PROJECT_ID is not configured');
  }

  const client = await getVerifier();

  let payload: FirebaseTokenPayload;
  try {
    // Identity Platform tokens are signed with the secure-token service certs
    // (not the OAuth2 federated certs verifyIdToken() uses), so fetch those
    // and verify against the Identity Platform issuer explicitly.
    const certs = await getSecureTokenCerts(client);
    const ticket = await client.verifySignedJwtWithCertsAsync(idToken, certs, projectId, [issuer(projectId)]);
    payload = ticket.getPayload() as FirebaseTokenPayload | undefined as never;
    if (!payload) {
      throw new TokenVerificationError('token has no payload');
    }
  } catch (err) {
    if (err instanceof TokenVerificationError) throw err;
    const msg = err instanceof Error ? err.message : String(err);
    throw new TokenVerificationError(`ID token verification failed: ${msg}`);
  }

  const tenantId = payload.firebase?.tenant ?? identity.defaultTenantId ?? '';
  if (!tenantId) {
    throw new TokenVerificationError('token is missing a tenant id');
  }

  const role = normalizeRole(payload.role);
  const email = payload.email ?? '';
  const uid = payload.sub ?? payload.user_id ?? '';
  if (!uid) {
    throw new TokenVerificationError('token is missing a subject (uid)');
  }

  return { uid, tenantId, role, email };
}

/** Default to the least-privileged role when the custom claim is absent/invalid. */
function normalizeRole(raw: unknown): UserRole {
  return typeof raw === 'string' && (USER_ROLES as readonly string[]).includes(raw) ? (raw as UserRole) : 'viewer';
}

/**
 * Fetch the secure-token x509 certificates Identity Platform tokens are signed
 * with. The OAuth2Client caches these by `Cache-Control` max-age internally; we
 * call the public x509 endpoint directly.
 */
async function getSecureTokenCerts(client: OAuth2Client): Promise<Record<string, string>> {
  const url = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
  const res = await client.transporter.request<Record<string, string>>({ url });
  return res.data;
}

/**
 * Minimal shape of an Identity Platform / Firebase ID-token payload — the
 * standard JWT claims plus the `firebase` block and our `role` custom claim.
 */
interface FirebaseTokenPayload {
  readonly sub?: string;
  readonly user_id?: string;
  readonly email?: string;
  readonly aud?: string;
  readonly iss?: string;
  readonly role?: unknown;
  readonly firebase?: {
    readonly tenant?: string;
    readonly sign_in_provider?: string;
  };
}
