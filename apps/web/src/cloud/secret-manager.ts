// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Google Secret Manager wrapper (ADR-017 / ADR-045).
 *
 * One secret resource per (tenant, user, provider). Only the key material lives
 * here — the provider/model choice is ordinary Postgres config. The reference
 * name is `shor/<tenant>/<user>/<provider>` (slashes flattened to a valid
 * Secret Manager id since secret ids may not contain `/`).
 *
 * Lazy client: the SDK `SecretManagerServiceClient` is constructed on first use,
 * never at import time, so `tsc`/`build` need no live GCP credentials.
 */

import type { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { getConfig } from '../config.js';

let client: SecretManagerServiceClient | undefined;

async function getClient(): Promise<SecretManagerServiceClient> {
  if (!client) {
    // Dynamic import keeps the GCP SDK out of the module-load path so importing
    // this file performs no I/O and needs no Application Default Credentials.
    const mod = await import('@google-cloud/secret-manager');
    client = new mod.SecretManagerServiceClient();
  }
  return client;
}

/**
 * Canonical secret reference for a (tenant, user, provider) triple:
 * `shor/<tenant>/<user>/<provider>` (ADR-017). Stored in `provider_key.secret_ref`.
 */
export function secretRef(tenantId: string, userId: string, provider: string): string {
  const { prefix } = getConfig().secrets;
  return `${prefix}/${sanitize(tenantId)}/${sanitize(userId)}/${sanitize(provider)}`;
}

/**
 * Convert a logical secret ref (`shor/<tenant>/<user>/<provider>`) into a valid
 * Secret Manager secret id. Ids must match `[A-Za-z0-9_-]+`, so path separators
 * collapse to `__`.
 */
export function secretIdFromRef(ref: string): string {
  return ref.replace(/\//g, '__');
}

function sanitize(part: string): string {
  return part.replace(/[^A-Za-z0-9_-]/g, '-');
}

function secretResourceName(projectId: string, ref: string): string {
  return `projects/${projectId}/secrets/${secretIdFromRef(ref)}`;
}

/**
 * Read the latest enabled version of the secret at `ref`. Returns the decoded
 * UTF-8 payload, or `null` when the secret/version does not exist.
 */
export async function getSecret(ref: string): Promise<string | null> {
  const { projectId } = getConfig().secrets;
  const c = await getClient();
  try {
    const [version] = await c.accessSecretVersion({
      name: `${secretResourceName(projectId, ref)}/versions/latest`,
    });
    const data = version.payload?.data;
    if (!data) return null;
    return Buffer.from(data).toString('utf8');
  } catch (err) {
    if (isNotFound(err)) return null;
    throw err;
  }
}

/**
 * Create the secret if missing, then add a new version holding `value`. Returns
 * the secret reference so callers can persist it in `provider_key.secret_ref`.
 */
export async function setSecret(ref: string, value: string): Promise<string> {
  const { projectId } = getConfig().secrets;
  const c = await getClient();
  const parent = `projects/${projectId}`;
  const secretId = secretIdFromRef(ref);

  try {
    await c.createSecret({
      parent,
      secretId,
      secret: { replication: { automatic: {} } },
    });
  } catch (err) {
    // AlreadyExists (gRPC code 6) is expected on re-set; rethrow anything else.
    if (!isAlreadyExists(err)) throw err;
  }

  await c.addSecretVersion({
    parent: secretResourceName(projectId, ref),
    payload: { data: Buffer.from(value, 'utf8') },
  });

  return ref;
}

/** Permanently delete the secret (and all versions) at `ref`. */
export async function deleteSecret(ref: string): Promise<void> {
  const { projectId } = getConfig().secrets;
  const c = await getClient();
  try {
    await c.deleteSecret({ name: secretResourceName(projectId, ref) });
  } catch (err) {
    if (!isNotFound(err)) throw err;
  }
}

function grpcCode(err: unknown): number | undefined {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const code = (err as { code: unknown }).code;
    return typeof code === 'number' ? code : undefined;
  }
  return undefined;
}

function isNotFound(err: unknown): boolean {
  return grpcCode(err) === 5; // gRPC NOT_FOUND
}

function isAlreadyExists(err: unknown): boolean {
  return grpcCode(err) === 6; // gRPC ALREADY_EXISTS
}
