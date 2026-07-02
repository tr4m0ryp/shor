// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Trigger a scan for a project (LAUNCH-SPEC §4, ADR-015/051).
 *
 * `POST /projects/:id/scan` is the Targets-view "Run scan" action. It:
 *   1. resolves the project's source into an immutable `CodebaseVersion`
 *      (`ingestForScan` — white-box clones the selected repo via the caller's
 *      GitHub PAT; black-box projects yield `null`, no code is staged),
 *   2. mints a `pending` scan row (`codebaseVersionId` null for black-box),
 *   3. builds the per-run secret-injection manifest for the selected provider,
 *   4. launches the Temporal workflow via `startScan` (which omits the repo URI
 *      when there is no codebase version).
 *
 * Authenticated + tenant-scoped via `gate()`; the principal supplies both the
 * `tenantId` (ingest/scoping) and the `uid` (whose provider + GitHub keys the
 * run uses).
 */

import { projectRepo, scanRepo } from '../../db/repositories/index.js';
import type { ProjectId, Provider } from '../../domain/types.js';
import { ingestForScan } from '../../ingest/index.js';
import { startScan } from '../../orchestration/index.js';
import { buildInjectionManifest } from '../../secrets/index.js';
import { mirrorScan } from '../../sinas/mirror.js';
import type { ApiResponse } from '../router.js';
import { badRequest, gate, notFound, ok, serverError } from './auth-util.js';

const PROVIDERS: ReadonlySet<Provider> = new Set<Provider>(['anthropic', 'openai', 'deepseek', 'openrouter', 'vertex']);

/**
 * `POST /projects/:id/scan` — resolve the project's source, mint a scan, and
 * start its Temporal workflow. Body (all optional):
 *   `{ provider?, ref? }`
 * `provider` selects which of the caller's provider keys the run file-mounts
 * (default `anthropic`). For white-box projects the selected repo is cloned via
 * the caller's stored GitHub PAT; black-box projects scan the target URL only.
 * Returns the started scan (and the codebase version when white-box).
 */
export async function triggerScan(
  projectId: ProjectId,
  body: Record<string, unknown>,
  cookieHeader: string | undefined,
): Promise<ApiResponse> {
  const g = gate(cookieHeader);
  if (!g.ok) return g.response;

  const provider = (typeof body.provider === 'string' ? body.provider : 'anthropic') as Provider;
  if (!PROVIDERS.has(provider)) return badRequest(`unknown provider: ${provider}`);

  const project = await projectRepo.findById(g.tenantId, projectId);
  if (!project) return notFound('project not found');

  try {
    const ingestOptions: Parameters<typeof ingestForScan>[1] = {
      tenantId: g.tenantId,
      userId: g.principal.uid,
      ...(typeof body.ref === 'string' ? { ref: body.ref } : {}),
    };
    // White-box → CodebaseVersion; black-box → null (scan carries no version).
    const codebaseVersion = await ingestForScan(project, ingestOptions);

    const scan = await scanRepo.create({
      projectId: project.id,
      codebaseVersionId: codebaseVersion ? codebaseVersion.id : null,
      temporalWorkflowId: null,
      status: 'pending',
    });

    const manifest = buildInjectionManifest(g.tenantId, g.principal.uid, provider);
    const started = await startScan(scan, project, codebaseVersion, manifest);

    // Best-effort hub->Sinas mirror of the freshly-started scan (enriched with the
    // project's live target); self-swallowing, never affects the response.
    await mirrorScan(started, { target: project.targetUrl });

    return ok({ scan: started, codebaseVersion });
  } catch (err) {
    return serverError(err);
  }
}
