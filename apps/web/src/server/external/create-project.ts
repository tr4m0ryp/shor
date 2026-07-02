// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `POST /external/projects` — Sinas creates a black-box or white-box project.
 *
 * The token-authed counterpart of the dashboard's `POST /projects` create. It
 * applies the SAME validation and persists via the SAME `projectRepo.create`,
 * scoped to the resolved showcase/owner tenant; the engine MINTS the projectId
 * (no client-supplied id — design T8).
 *
 * White-box: `repoRef` is one of the tenant's connected repos (`owner/name`); it
 * is stored as the project's `repoFullName`, so a later `POST /external/scans`
 * clones it with the engine's stored GitHub token EXACTLY as the dashboard does
 * (the clone happens at scan time via `ingestForScan`, not here). White-box with
 * no `repoRef` is rejected — there is nothing to clone. Black-box ignores any
 * `repoRef` and scans the target URL only.
 *
 * Body: `{ name, targetUrl, mode: 'blackbox'|'whitebox', repoRef? }`.
 * Returns `{ projectId }`.
 */

import type { Principal } from '../../auth/index.js';
import { projectRepo } from '../../db/repositories/index.js';
import type { NewProject, ProjectMode } from '../../domain/types.js';
import { badRequest, created, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

/** Parse a request `mode` field to a valid `ProjectMode`, or undefined. */
function parseMode(value: unknown): ProjectMode | undefined {
  return value === 'whitebox' || value === 'blackbox' ? value : undefined;
}

/** Normalize a `repoRef` to a trimmed `owner/name`, or null. */
function parseRepoRef(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export async function createExternalProject(principal: Principal, body: Record<string, unknown>): Promise<ApiResponse> {
  const tenantId = principal.tenantId;

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const targetUrl = typeof body.targetUrl === 'string' ? body.targetUrl.trim() : '';
  if (!name) return badRequest('name is required');
  if (!targetUrl) return badRequest('targetUrl is required');
  try {
    new URL(targetUrl);
  } catch {
    return badRequest('targetUrl is not a valid URL');
  }

  const repoFullName = parseRepoRef(body.repoRef);
  // Explicit mode wins; otherwise a present repoRef implies white-box.
  const mode = parseMode(body.mode) ?? (repoFullName ? 'whitebox' : 'blackbox');
  if (mode === 'whitebox' && !repoFullName) {
    return badRequest('whitebox projects require a repoRef (one of the connected repos)');
  }

  const authConfig =
    typeof body.authConfig === 'object' && body.authConfig !== null && !Array.isArray(body.authConfig)
      ? (body.authConfig as Record<string, unknown>)
      : null;

  const input: NewProject = {
    tenantId,
    name,
    targetUrl,
    repoInstallationId: null,
    // Black-box stores no repo even if a stray repoRef was sent.
    repoFullName: mode === 'whitebox' ? repoFullName : null,
    mode,
    schedule: null,
    authConfig,
  };

  try {
    const project = await projectRepo.create(input);
    return created({ projectId: project.id });
  } catch (err) {
    return serverError(err);
  }
}
