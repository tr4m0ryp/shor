// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Token-authed project reads for Sinas/MCP: list the tenant's projects and list
 * the scan history under one project. The `/external/*` counterparts of the
 * dashboard's Targets-view reads (dashboard `projects.ts`), scoped to the
 * resolved showcase/owner tenant. Read-only — no create/update/delete here (the
 * connector deliberately exposes no project-mutating tool).
 *
 *   GET /external/projects           -> { projects: [...] }
 *   GET /external/projects/:id/scans -> { scans: [...] }  (newest first)
 */

import type { Principal } from '../../auth/index.js';
import { projectRepo, scanRepo } from '../../db/repositories/index.js';
import type { ProjectId } from '../../domain/types.js';
import { notFound, ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

/** `GET /external/projects` — list the tenant's projects. */
export async function listExternalProjects(principal: Principal): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const projects = await projectRepo.listByTenant(tenantId);
    return ok({ projects });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /external/projects/:id/scans` — a project's scans, newest first. */
export async function listExternalProjectScans(principal: Principal, projectId: ProjectId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const project = await projectRepo.findById(tenantId, projectId);
    if (!project) return notFound('project not found');
    const scans = await scanRepo.listByProject(tenantId, projectId);
    return ok({ scans });
  } catch (err) {
    return serverError(err);
  }
}
