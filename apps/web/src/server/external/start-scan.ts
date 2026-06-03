/**
 * `POST /external/scans` — Sinas reruns/starts a scan for an existing project.
 *
 * The engine-side counterpart of the dashboard's `POST /projects/:id/scan`
 * trigger, but driven by a bearer token instead of a session. Reuses the SAME
 * in-process flow so behaviour stays identical: resolve the project (tenant-
 * scoped), `ingestForScan` (white-box clones the connected repo with the engine's
 * stored GitHub token; black-box yields null), mint a `pending` scan, build the
 * provider secret manifest, then `startScan`. The engine MINTS the scanId — a
 * client-supplied id in the body is ignored (design T8).
 *
 * Body: `{ projectId, ref?, provider? }`. Returns `{ scanId, status }`.
 */

import type { Principal } from '../../auth/index.js';
import { projectRepo, scanRepo } from '../../db/repositories/index.js';
import type { Provider } from '../../domain/types.js';
import { ingestForScan } from '../../ingest/index.js';
import { startScan } from '../../orchestration/index.js';
import { buildInjectionManifest } from '../../secrets/index.js';
import { badRequest, notFound, ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

const PROVIDERS: ReadonlySet<Provider> = new Set<Provider>(['anthropic', 'openai', 'deepseek', 'openrouter', 'vertex']);

export async function startExternalScan(principal: Principal, body: Record<string, unknown>): Promise<ApiResponse> {
  const tenantId = principal.tenantId;

  const projectId = typeof body.projectId === 'string' ? body.projectId.trim() : '';
  if (!projectId) return badRequest('projectId is required');

  const provider = (typeof body.provider === 'string' ? body.provider : 'anthropic') as Provider;
  if (!PROVIDERS.has(provider)) return badRequest(`unknown provider: ${provider}`);

  const project = await projectRepo.findById(tenantId, projectId);
  if (!project) return notFound('project not found');

  try {
    const ingestOptions: Parameters<typeof ingestForScan>[1] = {
      tenantId,
      userId: principal.uid,
      ...(typeof body.ref === 'string' ? { ref: body.ref } : {}),
    };
    // White-box -> CodebaseVersion; black-box -> null (scan carries no version).
    const codebaseVersion = await ingestForScan(project, ingestOptions);

    const scan = await scanRepo.create({
      projectId: project.id,
      codebaseVersionId: codebaseVersion ? codebaseVersion.id : null,
      temporalWorkflowId: null,
      status: 'pending',
    });

    const manifest = buildInjectionManifest(tenantId, principal.uid, provider);
    const started = await startScan(scan, project, codebaseVersion, manifest);

    return ok({ scanId: started.id, status: started.status });
  } catch (err) {
    return serverError(err);
  }
}
