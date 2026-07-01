/**
 * `GET /external/scans` — list the tenant's currently ACTIVE scans (the token-
 * authed "which runs are running?" read).
 *
 * Returns the in-flight scans (status `pending` or `running`) for the resolved
 * showcase/owner tenant, newest first, each as a compact snapshot mirroring the
 * single-scan read. Read-only; the engine mints nothing here.
 *
 * Returns `{ runs: [{ scanId, projectId, status, progress, startedAt }] }`.
 */

import type { Principal } from '../../auth/index.js';
import { scanRepo } from '../../db/repositories/index.js';
import { ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

export async function listActiveExternalScans(principal: Principal): Promise<ApiResponse> {
  try {
    const scans = await scanRepo.listActive(principal.tenantId);
    const runs = scans.map((s) => ({
      scanId: s.id,
      projectId: s.projectId,
      status: s.status,
      progress: s.progress,
      startedAt: s.startedAt,
    }));
    return ok({ runs });
  } catch (err) {
    return serverError(err);
  }
}
