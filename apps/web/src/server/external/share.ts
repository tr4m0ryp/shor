/**
 * `POST /external/projects/:id/share` — mint (or read) a project's read-only
 * guest link over the token-authed external plane.
 *
 * The engine-side counterpart of the dashboard's `POST /projects/:id/share`:
 * idempotent (an already-shared project returns its existing slug, so the link
 * never rotates), tenant-scoped to the resolved external principal, and READ-ONLY
 * with respect to scanning — it only ever exposes that one project's results. The
 * MCP connector's `get_share_url` wraps this; the returned `shareUrl` is the sole
 * client-facing output of a run.
 *
 * Returns `{ shareSlug, shareUrl }`. `shareUrl` is the dashboard's public base
 * URL with `?share=<slug>` (the entry the SPA uses to enter guest mode).
 */

import { randomBytes } from 'node:crypto';
import type { Principal } from '../../auth/index.js';
import { getConfig } from '../../config.js';
import { projectRepo } from '../../db/repositories/index.js';
import type { ProjectId } from '../../domain/types.js';
import { notFound, ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

/** Compose the guest URL from the configured public base and the slug. */
function shareUrlFor(slug: string): string {
  const base = getConfig().publicUrl.replace(/\/+$/, '');
  return `${base}/?share=${encodeURIComponent(slug)}`;
}

export async function shareExternalProject(principal: Principal, projectId: ProjectId): Promise<ApiResponse> {
  const tenantId = principal.tenantId;
  try {
    const project = await projectRepo.findById(tenantId, projectId);
    if (!project) return notFound('project not found');

    const slug = project.shareSlug ?? randomBytes(12).toString('base64url');
    if (!project.shareSlug) {
      const updated = await projectRepo.setShareSlug(tenantId, projectId, slug);
      if (!updated) return notFound('project not found');
    }
    return ok({ shareSlug: slug, shareUrl: shareUrlFor(slug) });
  } catch (err) {
    return serverError(err);
  }
}
