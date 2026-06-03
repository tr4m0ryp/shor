/**
 * Per-run secret injection manifest (LAUNCH-SPEC §3.2, ADR-017 / ADR-045 / ADR-050).
 *
 * The load-bearing contract between the control plane (dashboard) and a scan's
 * Cloud Run Job. For a given (tenant, user, selectedProvider) it produces:
 *
 *   1. The SINGLE `secretRef` to file-mount — only the one provider key chosen
 *      for the run, never the user's whole keyring.
 *   2. The mount path + the env var (`SHOR_PROVIDER_KEY_FILE`) the engine reads
 *      at use time. Secrets are mounted as VOLUME FILES, not env values, so the
 *      key cannot leak via `/proc/<pid>/environ` (ADR-045).
 *   3. The scoped service-identity binding contract: the per-run identity may be
 *      granted `roles/secretmanager.secretAccessor` on ONLY this tenant's
 *      secrets, and the manifest names the exact secret it must reach.
 *
 * This module is pure config derivation — it performs no I/O and constructs no
 * GCP clients, so importing it needs no live credentials.
 */

import { secretRef, secretIdFromRef } from '../cloud/secret-manager.js';
import { getConfig } from '../config.js';
import type { Provider, TenantId, UserId } from '../domain/types.js';

/**
 * The env var the engine reads to locate the file-mounted provider key
 * (ADR-050). Mirrors `apps/worker/.../sdk-env.ts` (`SHOR_PROVIDER_KEY_FILE`).
 */
export const PROVIDER_KEY_FILE_ENV = 'SHOR_PROVIDER_KEY_FILE';

/** Container path the provider-key secret volume is mounted at. */
export const PROVIDER_KEY_MOUNT_DIR = '/secrets/provider';

/** Filename of the mounted provider-key payload within the mount dir. */
export const PROVIDER_KEY_FILE_NAME = 'key';

/**
 * Scoped service-identity binding contract: which tenant's secrets the run's
 * identity may access, and the exact secret resource to bind
 * `roles/secretmanager.secretAccessor` on. The identity is granted access to
 * NOTHING beyond this single secret (ADR-018 identity isolation).
 */
export interface SecretAccessBinding {
  /** Tenant whose secret namespace the run is confined to. */
  readonly tenantId: TenantId;
  /** IAM role to bind on the per-run service identity. */
  readonly role: 'roles/secretmanager.secretAccessor';
  /** Logical secret reference the identity may read (the only one). */
  readonly secretRef: string;
  /** Secret Manager resource id derived from `secretRef`. */
  readonly secretId: string;
  /** Fully-qualified Secret Manager resource name for the IAM binding. */
  readonly secretResourceName: string;
}

/** A secret to file-mount into the run container. */
export interface FileMountSecret {
  /** Logical secret reference (`shor/<tenant>/<user>/<provider>`). */
  readonly secretRef: string;
  /** Secret Manager secret id. */
  readonly secretId: string;
  /** Directory the secret volume is mounted at. */
  readonly mountDir: string;
  /** Absolute path to the mounted payload file. */
  readonly mountPath: string;
  /** Env var the engine reads to find `mountPath` (file path, not material). */
  readonly envVar: string;
}

/** Per-run injection manifest for a single scan. */
export interface InjectionManifest {
  readonly tenantId: TenantId;
  readonly userId: UserId;
  readonly provider: Provider;
  /** The ONE provider key to file-mount for this run. */
  readonly providerKeyMount: FileMountSecret;
  /** IAM scoping contract for the per-run service identity. */
  readonly identityBinding: SecretAccessBinding;
}

/**
 * Build the per-run injection manifest for a scan. Injects ONLY the one selected
 * provider key and confines the run identity to that tenant's secrets.
 *
 * Pure: derives refs/paths from config; the caller (job launcher) applies the
 * mount + IAM binding against GCP.
 */
export function buildInjectionManifest(
  tenantId: TenantId,
  userId: UserId,
  selectedProvider: Provider,
): InjectionManifest {
  const ref = secretRef(tenantId, userId, selectedProvider);
  const secretId = secretIdFromRef(ref);
  const { projectId } = getConfig().secrets;
  const secretResourceName = `projects/${projectId}/secrets/${secretId}`;
  const mountPath = `${PROVIDER_KEY_MOUNT_DIR}/${PROVIDER_KEY_FILE_NAME}`;

  return {
    tenantId,
    userId,
    provider: selectedProvider,
    providerKeyMount: {
      secretRef: ref,
      secretId,
      mountDir: PROVIDER_KEY_MOUNT_DIR,
      mountPath,
      envVar: PROVIDER_KEY_FILE_ENV,
    },
    identityBinding: {
      tenantId,
      role: 'roles/secretmanager.secretAccessor',
      secretRef: ref,
      secretId,
      secretResourceName,
    },
  };
}
