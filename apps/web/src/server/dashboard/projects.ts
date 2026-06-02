/**
 * Dashboard projects API (LAUNCH-SPEC §4 project model, ADR-015).
 *
 * A project = a named target (live site + connected repo + optional schedule).
 * These handlers back the Targets view: create / list / get / update / delete a
 * project, and list the scans under it. Every handler is authenticated and
 * tenant-scoped via `gate()` — the principal's verified `tenantId` is the only
 * tenant id the repositories ever see, so a caller can never name another
 * tenant's project.
 */

import { randomBytes } from 'node:crypto';
import { projectRepo, scanRepo } from '../../db/repositories/index.js';
import type { NewProject, ProjectId, ProjectMode } from '../../domain/types.js';
import type { ApiResponse } from '../router.js';
import { badRequest, created, gate, notFound, ok, serverError } from './auth-util.js';

/** Parse a request `mode` field to a valid `ProjectMode`, or undefined. */
function parseMode(value: unknown): ProjectMode | undefined {
  return value === 'whitebox' || value === 'blackbox' ? value : undefined;
}

/** Normalize a request `repoFullName` to a trimmed `owner/name`, or null. */
function parseRepoFullName(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/** `GET /projects` — list the caller-tenant's projects (Targets view). */
export async function listProjects(cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const projects = await projectRepo.listByTenant(g.tenantId);
    return ok({ projects });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `POST /projects` — create a project (Targets view). Body:
 * `{ name, targetUrl, repoFullName?, mode?, repoInstallationId?, schedule?, authConfig? }`.
 * A selected `repoFullName` defaults `mode` to white-box; otherwise black-box.
 */
export async function createProject(
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const targetUrl = typeof body.targetUrl === 'string' ? body.targetUrl.trim() : '';
  if (!name) return badRequest('name is required');
  if (!targetUrl) return badRequest('targetUrl is required');
  try {
    new URL(targetUrl);
  } catch {
    return badRequest('targetUrl is not a valid URL');
  }

  const repoInstallationId =
    typeof body.repoInstallationId === 'string' && body.repoInstallationId.trim()
      ? body.repoInstallationId.trim()
      : null;
  const schedule = typeof body.schedule === 'string' && body.schedule.trim() ? body.schedule.trim() : null;
  const authConfig =
    typeof body.authConfig === 'object' && body.authConfig !== null && !Array.isArray(body.authConfig)
      ? (body.authConfig as Record<string, unknown>)
      : null;

  const repoFullName = parseRepoFullName(body.repoFullName);
  const mode = parseMode(body.mode) ?? (repoFullName ? 'whitebox' : 'blackbox');

  const input: NewProject = {
    tenantId: g.tenantId,
    name,
    targetUrl,
    repoInstallationId,
    repoFullName,
    mode,
    schedule,
    authConfig,
  };
  try {
    const project = await projectRepo.create(input);
    return created({ project });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /projects/:id` — fetch one project (tenant-scoped). */
export async function getProject(id: ProjectId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const project = await projectRepo.findById(g.tenantId, id);
    return project ? ok({ project }) : notFound('project not found');
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `PUT /projects/:id` — patch mutable project fields (name / targetUrl /
 * repoFullName / mode / repoInstallationId / schedule / authConfig). Only
 * provided keys are changed; setting `repoFullName` re-derives `mode`.
 */
export async function updateProject(
  id: ProjectId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;

  const patch: Record<string, unknown> = {};
  if (typeof body.name === 'string') patch.name = body.name.trim();
  if (typeof body.targetUrl === 'string') {
    const url = body.targetUrl.trim();
    try {
      new URL(url);
    } catch {
      return badRequest('targetUrl is not a valid URL');
    }
    patch.targetUrl = url;
  }
  if ('repoInstallationId' in body) {
    patch.repoInstallationId =
      typeof body.repoInstallationId === 'string' && body.repoInstallationId.trim()
        ? body.repoInstallationId.trim()
        : null;
  }
  // A present `repoFullName` (incl. explicit null/"" → black-box) re-derives mode
  // unless an explicit `mode` is also supplied.
  if ('repoFullName' in body) {
    patch.repoFullName = parseRepoFullName(body.repoFullName);
  }
  const mode = parseMode(body.mode);
  if (mode) patch.mode = mode;
  if ('schedule' in body) {
    patch.schedule = typeof body.schedule === 'string' && body.schedule.trim() ? body.schedule.trim() : null;
  }
  if (typeof body.authConfig === 'object' && body.authConfig !== null && !Array.isArray(body.authConfig)) {
    patch.authConfig = body.authConfig as Record<string, unknown>;
  }

  try {
    const project = await projectRepo.update(g.tenantId, id, patch);
    return project ? ok({ project }) : notFound('project not found');
  } catch (err) {
    return serverError(err);
  }
}

/** `DELETE /projects/:id` — remove a project (tenant-scoped). */
export async function deleteProject(id: ProjectId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    await projectRepo.delete(g.tenantId, id);
    return ok({ ok: true });
  } catch (err) {
    return serverError(err);
  }
}

/** `GET /projects/:id/scans` — list a project's scans, newest first. */
export async function listProjectScans(id: ProjectId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const project = await projectRepo.findById(g.tenantId, id);
    if (!project) return notFound('project not found');
    const scans = await scanRepo.listByProject(g.tenantId, id);
    return ok({ scans });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `POST /projects/:id/share` — mint (or return the existing) read-only guest
 * link slug for a project. Idempotent: a project that is already shared returns
 * its current slug so re-clicking "Share" never rotates a live link. The slug is
 * a URL-safe 16-char random token (12 bytes → base64url), opaque and
 * unguessable; it is the sole access key the public `/share/:slug/...` routes
 * resolve.
 */
export async function shareProject(id: ProjectId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const project = await projectRepo.findById(g.tenantId, id);
    if (!project) return notFound('project not found');
    if (project.shareSlug) return ok({ shareSlug: project.shareSlug });
    const slug = randomBytes(12).toString('base64url');
    const updated = await projectRepo.setShareSlug(g.tenantId, id, slug);
    if (!updated) return notFound('project not found');
    return ok({ shareSlug: updated.shareSlug });
  } catch (err) {
    return serverError(err);
  }
}

/**
 * `DELETE /projects/:id/share` — revoke a project's guest link (clears the
 * slug). Any outstanding `?share=<slug>` URL stops resolving immediately.
 */
export async function unshareProject(id: ProjectId, cookieHeader: string | undefined): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;
  try {
    const updated = await projectRepo.setShareSlug(g.tenantId, id, null);
    if (!updated) return notFound('project not found');
    return ok({ ok: true });
  } catch (err) {
    return serverError(err);
  }
}
