// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Web-layer Sinas mirror (engine -> Sinas state push).
 *
 * The web control plane is the source of truth; this module pushes a faithful,
 * idempotent COPY of project / scan / findings state into the user's Sinas
 * `pentest` KV stores on the events the dashboard already handles, so a run is
 * visible live in Sinas — not just at finalize.
 *
 * Best-effort and non-blocking (mirrors `apps/worker/src/job/sinas-finalization.ts`):
 *   - every call is wrapped in try/catch; failures are logged + swallowed and
 *     NEVER change a handler's success/error behavior,
 *   - when Sinas is not configured (`sinasUrl`/`sinasApiKey` empty) every mirror
 *     is a silent no-op.
 *
 * Upsert is `PUT ${sinasUrl}/stores/${sinasNamespace}/<store>/states/<key>` with
 * header `X-API-Key: <sinasApiKey>` and body `{ value, tags? }`. Keys are the
 * stable ids: `projects/{projectId}`, `scans/{scanId}`, `findings/{fingerprint}`.
 * The value always carries an `updatedAt`, so an overwrite by the same key is a
 * harmless idempotent refresh (it intentionally overlaps the worker's finalize
 * push of findings by fingerprint).
 *
 * `apps/web` cannot import across apps, so the tiny `X-API-Key` fetch helper is
 * replicated here from the worker's finalization module.
 */

import { getConfig } from '../config.js';
import type { FindingRecord, Project, Scan, ScanId } from '../domain/types.js';

/** Resolved outbound Sinas connection (host + key + namespace). */
interface SinasConnection {
  readonly url: string;
  readonly apiKey: string;
  readonly namespace: string;
}

/**
 * Resolve the outbound Sinas connection from `getConfig().sinas` (task 001).
 * Returns null — making every mirror a silent no-op — unless BOTH the base URL
 * and the API key are configured. The trailing slash is trimmed so the path we
 * append composes cleanly.
 */
function resolveConnection(): SinasConnection | null {
  const { sinasUrl, sinasApiKey, sinasNamespace } = getConfig().sinas;
  if (!sinasUrl || !sinasApiKey) return null;
  return { url: sinasUrl.replace(/\/+$/, ''), apiKey: sinasApiKey, namespace: sinasNamespace || 'pentest' };
}

/** `X-API-Key` JSON fetch against the Sinas instance (replicated from the worker). */
async function sinasFetch(conn: SinasConnection, method: string, apiPath: string, body?: unknown): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: { 'X-API-Key': conn.apiKey, 'Content-Type': 'application/json' },
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  return fetch(`${conn.url}${apiPath}`, init);
}

/**
 * Idempotent upsert of one KV state: `PUT /stores/<ns>/<store>/states/<key>`
 * with `{ value, tags? }`. Best-effort — any rejection (config-less no-op aside)
 * is logged + swallowed so a Sinas hiccup can never reject the caller's request.
 */
async function upsertState(
  conn: SinasConnection,
  store: string,
  key: string,
  value: unknown,
  tags?: readonly string[],
): Promise<void> {
  const path = `/stores/${conn.namespace}/${store}/states/${encodeURIComponent(key)}`;
  const body = tags && tags.length > 0 ? { value, tags } : { value };
  try {
    const res = await sinasFetch(conn, 'PUT', path, body);
    if (!res.ok) {
      console.error(`[sinas-mirror] upsert "${store}/${key}" failed:`, res.status);
    }
  } catch (err) {
    console.error(`[sinas-mirror] upsert "${store}/${key}" failed:`, err);
  }
}

/** ISO timestamp stamped onto every mirrored value for last-write visibility. */
function now(): string {
  return new Date().toISOString();
}

/**
 * Mirror a project into `pentest/projects`, keyed by `projectId`. The value is a
 * faithful copy of the project row plus an `updatedAt`. Best-effort; no-op when
 * Sinas is unconfigured.
 */
export async function mirrorProject(project: Project): Promise<void> {
  const conn = resolveConnection();
  if (!conn) return;
  const value = { ...project, updatedAt: now() };
  await upsertState(conn, 'projects', project.id, value, [project.mode]);
}

/** Extra context a call site may have for a scan but the {@link Scan} row lacks. */
export interface ScanMirrorMeta {
  /** Live target URL (lives on the project, not the scan); enriches the value. */
  readonly target?: string;
}

/**
 * Mirror a scan into `pentest/scans`, keyed by `scanId`. The value is
 * status + the live progress snapshot + meta (projectId, target, startedAt,
 * finishedAt). The progress handler fires every few seconds during a run, so
 * repeated overwrites by the same `scanId` give Sinas a near-real-time view.
 * Best-effort; no-op when Sinas is unconfigured.
 */
export async function mirrorScan(scan: Scan, meta?: ScanMirrorMeta): Promise<void> {
  const conn = resolveConnection();
  if (!conn) return;
  const value = {
    id: scan.id,
    projectId: scan.projectId,
    status: scan.status,
    startedAt: scan.startedAt,
    finishedAt: scan.finishedAt,
    progress: scan.progress,
    ...(meta?.target !== undefined ? { target: meta.target } : {}),
    updatedAt: now(),
  };
  await upsertState(conn, 'scans', scan.id, value, [scan.status]);
}

/**
 * Mirror a batch of findings into `pentest/findings`, each keyed by its stable
 * `fingerprint` (the same key the worker's finalize push uses, so overlap is an
 * idempotent overwrite). The `scanId` is carried in the value so a finding state
 * links back to its run. Best-effort; no-op when Sinas is unconfigured. Findings
 * missing a fingerprint are skipped (nothing stable to key on).
 */
export async function mirrorFindings(scanId: ScanId, findings: readonly FindingRecord[]): Promise<void> {
  const conn = resolveConnection();
  if (!conn || findings.length === 0) return;
  const updatedAt = now();
  for (const finding of findings) {
    const key = finding.fingerprint || finding.id;
    if (!key) continue;
    const value = { ...finding, scanId, updatedAt };
    await upsertState(conn, 'findings', key, value, [finding.severity, finding.status]);
  }
}
