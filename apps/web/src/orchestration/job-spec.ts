// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cloud Run Job resource spec builder (ADR-018 / ADR-051).
 *
 * The per-run identity and the scoped Secret Manager volume mount are MANDATORY
 * and cannot be set in a `runJob` override (the v2 API only allows env/args/
 * timeout overrides at run time). So we bake them into a per-scan Job resource:
 *   - `serviceAccount` = the per-run identity scoped to the tenant's secrets.
 *   - a single `secret` volume mounting ONLY the selected provider key
 *     (`InjectionManifest.providerKeyMount`) as a file under the mount dir.
 *
 * Pure: derives the proto plain-object spec from config + manifest. No I/O, no
 * GCP client — importing it needs no live credentials.
 */

import type { CloudRunConfig } from '../config.js';
import type { InjectionManifest } from '../secrets/injection.js';

/** A run-Job container env var (name/value pair). */
export interface JobEnvVar {
  readonly name: string;
  readonly value: string;
}

/** Default container name Cloud Run assigns single-container Jobs. */
export const SCAN_CONTAINER_NAME = 'scan';

/** Volume name for the file-mounted provider-key secret. */
const PROVIDER_KEY_VOLUME = 'provider-key';

/** `projects/<project>/locations/<region>` parent for Job create/run. */
export function jobParent(cfg: CloudRunConfig): string {
  return `projects/${cfg.projectId}/locations/${cfg.region}`;
}

/** Fully-qualified Job resource name `…/jobs/<jobId>`. */
export function jobName(cfg: CloudRunConfig, jobId: string): string {
  return `${jobParent(cfg)}/jobs/${jobId}`;
}

/**
 * Resolve the per-run service-identity email by substituting `{tenantId}` in the
 * configured template, so `secretAccessor` is scoped to that tenant (ADR-018).
 */
export function resolveRunServiceAccount(cfg: CloudRunConfig, tenantId: string): string {
  return cfg.runServiceAccount.replace('{tenantId}', tenantId);
}

/**
 * Build the per-scan Cloud Run Job resource (plain proto object). Carries the
 * per-run identity + the single scoped secret volume mount; baseline env is set
 * here and the per-run env (scan id, target, repo URI) is layered at run time.
 */
export function buildScanJob(
  cfg: CloudRunConfig,
  manifest: InjectionManifest,
  baseEnv: readonly JobEnvVar[],
): Record<string, unknown> {
  const { providerKeyMount } = manifest;
  const serviceAccount = resolveRunServiceAccount(cfg, manifest.tenantId);
  // The mounted filename within the mount dir, e.g. 'key' from '/secrets/provider/key'.
  const keyFileName = providerKeyMount.mountPath.slice(providerKeyMount.mountDir.length + 1);

  return {
    template: {
      template: {
        serviceAccount,
        maxRetries: 0,
        timeout: { seconds: cfg.taskTimeoutSeconds },
        executionEnvironment: 'EXECUTION_ENVIRONMENT_GEN2',
        ...(cfg.encryptionKey ? { encryptionKey: cfg.encryptionKey } : {}),
        ...(cfg.vpcConnector
          ? { vpcAccess: { connector: cfg.vpcConnector, egress: cfg.vpcEgress } }
          : {}),
        containers: [
          {
            name: SCAN_CONTAINER_NAME,
            image: cfg.workerImage,
            command: [...cfg.jobCommand],
            env: baseEnv.map((e) => ({ name: e.name, value: e.value })),
            resources: { limits: { cpu: cfg.cpu, memory: cfg.memory } },
            volumeMounts: [{ name: PROVIDER_KEY_VOLUME, mountPath: providerKeyMount.mountDir }],
          },
        ],
        volumes: [
          {
            name: PROVIDER_KEY_VOLUME,
            secret: {
              // The ONE selected provider key, mounted as a file (ADR-045).
              secret: providerKeyMount.secretId,
              items: [{ path: keyFileName, version: 'latest' }],
            },
          },
        ],
      },
    },
  };
}

/**
 * Build the `runJob` override env list for one scan. These layer on top of the
 * Job's baseline container env at run time (the only override the API supports
 * besides args/timeout).
 */
export function buildRunOverrides(env: readonly JobEnvVar[]): Record<string, unknown> {
  return {
    containerOverrides: [
      {
        name: SCAN_CONTAINER_NAME,
        env: env.map((e) => ({ name: e.name, value: e.value })),
        clearArgs: false,
      },
    ],
  };
}
