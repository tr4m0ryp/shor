// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * HTTP handlers for the live run-progress feed (ADR-051).
 *
 *   - POST /scans/:id/progress — the worker pushes a snapshot as it walks the
 *     pipeline. Dual auth (service token or session), reusing the findings
 *     sink's `resolveSinkTenant`. Best-effort: validates, persists, returns ok.
 *   - GET  /scans/:id/progress — the dashboard polls this; returns the derived
 *     phase/agent view (session-gated, tenant-scoped).
 */

import { scanRepo } from '../db/repositories/index.js';
import type { AgentProgress, ScanId, ScanProgress, ScanStatus } from '../domain/types.js';
import { resolveSinkTenant } from '../findings/index.js';
import type { ApiResponse } from '../server/router.js';
import { gate, notFound, ok, serverError } from '../server/dashboard/auth-util.js';
import { mirrorScan } from '../sinas/mirror.js';
import { deriveProgressView } from './derive.js';

const STATUSES: ReadonlySet<string> = new Set(['pending', 'running', 'completed', 'failed', 'cancelled']);

function asStatus(v: unknown, fallback: ScanStatus): ScanStatus {
  return typeof v === 'string' && STATUSES.has(v) ? (v as ScanStatus) : fallback;
}

function asStr(v: unknown): string | null {
  return typeof v === 'string' && v ? v : null;
}

/** Coerce the posted `completedAgents` array into validated records. */
function asCompleted(v: unknown): AgentProgress[] {
  if (!Array.isArray(v)) return [];
  const out: AgentProgress[] = [];
  for (const item of v) {
    if (typeof item !== 'object' || item === null) continue;
    const r = item as Record<string, unknown>;
    const agent = asStr(r.agent);
    if (!agent) continue;
    const status = r.status === 'failed' ? 'failed' : 'completed';
    const durationMs = typeof r.durationMs === 'number' && Number.isFinite(r.durationMs) ? r.durationMs : 0;
    const num = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
    const startedAt = num(r.startedAt);
    const finishedAt = num(r.finishedAt);
    out.push({
      agent,
      status,
      durationMs,
      ...(startedAt !== undefined ? { startedAt } : {}),
      ...(finishedAt !== undefined ? { finishedAt } : {}),
    });
  }
  return out;
}

/** Coerce the posted `starts` map (agent → epoch ms). */
function asStarts(v: unknown): Record<string, number> {
  if (typeof v !== 'object' || v === null) return {};
  const out: Record<string, number> = {};
  for (const [agent, ms] of Object.entries(v as Record<string, unknown>)) {
    if (typeof ms === 'number' && Number.isFinite(ms)) out[agent] = ms;
  }
  return out;
}

/** Coerce the posted `skills` map (agent → string[]) into a clean record. */
function asSkills(v: unknown): Record<string, string[]> {
  if (typeof v !== 'object' || v === null) return {};
  const out: Record<string, string[]> = {};
  for (const [agent, list] of Object.entries(v as Record<string, unknown>)) {
    if (!Array.isArray(list)) continue;
    const skills = list.filter((s): s is string => typeof s === 'string' && s.length > 0);
    if (skills.length) out[agent] = skills;
  }
  return out;
}

/**
 * `POST /scans/:id/progress` — persist the worker's latest progress snapshot.
 * Body: `{ status?, currentPhase?, currentAgent?, failedAgent?, completedAgents? }`.
 */
export async function handleIngestProgress(
  scanId: ScanId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
  authHeader?: string | undefined,
): Promise<ApiResponse> {
  const resolved = await resolveSinkTenant(scanId, cookieHeader, authHeader);
  if (!resolved.ok) return { status: resolved.status, body: { error: resolved.error } };

  const snapshot: ScanProgress = {
    status: asStatus(body.status, 'running'),
    currentPhase: asStr(body.currentPhase),
    currentAgent: asStr(body.currentAgent),
    failedAgent: asStr(body.failedAgent),
    runningAgents: Array.isArray(body.runningAgents)
      ? body.runningAgents.filter((a): a is string => typeof a === 'string' && a.length > 0)
      : [],
    starts: asStarts(body.starts),
    completedAgents: asCompleted(body.completedAgents),
    skills: asSkills(body.skills),
    updatedAt: new Date().toISOString(),
  };

  try {
    const updated = await scanRepo.setProgress(resolved.tenantId, scanId, snapshot);
    if (!updated) return notFound('scan not found');
    // Best-effort hub->Sinas mirror of the live progress snapshot (~3s cadence
    // during a run -> near-real-time in Sinas); self-swallowing, never blocks.
    await mirrorScan(updated);
    return ok({ ok: true });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /scans/:id/progress` — the derived phase/agent feed for the activity tab. */
export async function getScanProgress(scanId: ScanId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const scan = await scanRepo.findById(g.tenantId, scanId);
    if (!scan) return notFound('scan not found');
    return ok({ progress: deriveProgressView(scan) });
  } catch (err) {
    return serverError(err);
  }
}
