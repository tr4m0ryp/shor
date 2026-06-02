/**
 * Trigger a scan for a project (LAUNCH-SPEC §4, ADR-015/051).
 *
 * `POST /projects/:id/scan` is the Targets-view "Run scan" action. It:
 *   1. ingests the project's source into an immutable `CodebaseVersion`
 *      (`ingestForScan` — GitHub pull for connected repos, zip otherwise),
 *   2. mints a `pending` scan row,
 *   3. builds the per-run secret-injection manifest for the selected provider,
 *   4. launches the Temporal workflow via `startScan`.
 *
 * Authenticated + tenant-scoped via `gate()`; the principal supplies both the
 * `tenantId` (ingest/scoping) and the `uid` (whose provider key the run mounts).
 */

import { projectRepo, scanRepo } from '../../db/repositories/index.js';
import type { ProjectId, Provider } from '../../domain/types.js';
import { ingestForScan } from '../../ingest/index.js';
import { startScan } from '../../orchestration/index.js';
import { buildInjectionManifest } from '../../secrets/index.js';
import type { ApiResponse } from '../router.js';
import { badRequest, gate, notFound, ok, serverError } from './auth-util.js';

const PROVIDERS: ReadonlySet<Provider> = new Set<Provider>(['anthropic', 'openai', 'deepseek', 'openrouter', 'vertex']);

/** Decode the zip upload (base64 `zip` field) for projects with no connected repo. */
function decodeZip(body: Record<string, unknown>): { archive: Buffer; filename?: string } | undefined {
  const zip = body.zip;
  if (typeof zip !== 'string' || !zip) return undefined;
  const archive = Buffer.from(zip, 'base64');
  const filename = typeof body.zipFilename === 'string' ? body.zipFilename : undefined;
  return filename !== undefined ? { archive, filename } : { archive };
}

/**
 * `POST /projects/:id/scan` — ingest the project's source, mint a scan, and
 * start its Temporal workflow. Body (all optional):
 *   `{ provider?, repoFullName?, ref?, zip?, zipFilename? }`
 * `provider` selects which of the caller's provider keys the run file-mounts
 * (default `anthropic`). `zip` (base64) is required for projects with no
 * connected repo. Returns the started scan.
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
    const zip = decodeZip(body);
    const ingestOptions: Parameters<typeof ingestForScan>[1] = {
      tenantId: g.tenantId,
      ...(typeof body.repoFullName === 'string' ? { repoFullName: body.repoFullName } : {}),
      ...(typeof body.ref === 'string' ? { ref: body.ref } : {}),
      ...(zip ? { zip } : {}),
    };
    const codebaseVersion = await ingestForScan(project, ingestOptions);

    const scan = await scanRepo.create({
      projectId: project.id,
      codebaseVersionId: codebaseVersion.id,
      temporalWorkflowId: null,
      status: 'pending',
    });

    const manifest = buildInjectionManifest(g.tenantId, g.principal.uid, provider);
    const started = await startScan(scan, project, codebaseVersion, manifest);

    return ok({ scan: started, codebaseVersion });
  } catch (err) {
    return serverError(err);
  }
}
