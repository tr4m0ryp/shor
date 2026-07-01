/**
 * `POST /external/launch` — the token-gated black-box launch (MCP connector).
 *
 * This is the ONE path a Claude routine can use to start a scan, and it is the
 * gate: it refuses unless the body carries a valid, single-use, scope-bound,
 * unexpired launch token that only the operator's approval backend can mint. The
 * gate runs INSIDE the trusted control plane (not the MCP edge) and consumes the
 * token in the SAME atomic step it validates it, so the rejection is
 * unbypassable and race-free.
 *
 * Body: `{ engagementId, authorizationToken, roe }` where `roe` is the signed
 * DEFAULT-DENY allowlist. Flow:
 *   1. validate the RoE shape (invalid → 400, before any token work),
 *   2. atomically validate+consume the token bound to THIS engagement + a hash of
 *      THIS RoE (mismatch/expired/used/absent → 403, the gate),
 *   3. create a black-box project with the SIGNED RoE ATTACHED so Shor's own
 *      default-deny enforces the identical allowlist, then start the scan,
 *   4. write the audit line linking engagement → roeHash → grant → scan.
 *
 * Returns `{ projectId, scanId, status }`. The token and any secret are never
 * echoed back and never logged.
 */

import type { Principal } from '../../auth/index.js';
import { launchTokenRepo, projectRepo, scanRepo } from '../../db/repositories/index.js';
import type { NewProject } from '../../domain/types.js';
import { getAuditTee } from '../../guardrails/audit.js';
import { hashRoe } from '../../guardrails/roe-hash.js';
import { type Roe, validateRoe } from '../../guardrails/roe.js';
import { ingestForScan } from '../../ingest/index.js';
import { startScan } from '../../orchestration/index.js';
import { buildInjectionManifest } from '../../secrets/index.js';
import { badRequest, ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

const REJECTED: ApiResponse = { status: 403, body: { error: 'launch token rejected' } };

/** The distinct hostnames an RoE authorizes — recorded in the audit line. */
function targetHosts(roe: Roe): string[] {
  return [...new Set(roe.allowedHosts.map((h) => h.host.trim().toLowerCase()).filter(Boolean))];
}

export async function launchExternalScan(principal: Principal, body: Record<string, unknown>): Promise<ApiResponse> {
  const tenantId = principal.tenantId;

  const engagementId = typeof body.engagementId === 'string' ? body.engagementId.trim() : '';
  const authorizationToken = typeof body.authorizationToken === 'string' ? body.authorizationToken : '';
  if (!engagementId) return badRequest('engagementId is required');
  if (!authorizationToken) return badRequest('authorizationToken is required');

  // Validate the RoE shape BEFORE touching the token, so a malformed scope never
  // consumes a token. `validateRoe` also rejects an empty allowlist (default-deny).
  const rawRoe = typeof body.roe === 'object' && body.roe !== null && !Array.isArray(body.roe) ? (body.roe as Roe) : null;
  if (!rawRoe) return badRequest('roe is required');
  const validated = validateRoe(rawRoe);
  if (!validated.ok) {
    return { status: 400, body: { error: 'invalid roe', details: validated.errors } };
  }
  const roe = validated.roe;
  const roeHash = hashRoe(rawRoe);

  try {
    // The gate: validate + single-use consume in one atomic statement. A null
    // result means the token was absent, already used, expired, or bound to a
    // different engagement or RoE — every one of those is an unauthorized launch.
    const grant = await launchTokenRepo.consume({ token: authorizationToken, engagementId, roeHash });
    if (!grant) return REJECTED;

    // Black-box project with the SIGNED RoE attached. targetUrl comes from the RoE
    // (the operator signed it); the persisted RoE is what the worker enforces.
    const input: NewProject = {
      tenantId,
      name: `MCP engagement ${engagementId}`,
      targetUrl: roe.targetUrl,
      repoInstallationId: null,
      repoFullName: null,
      mode: 'blackbox',
      schedule: null,
      authConfig: null,
      roe: roe as unknown as Record<string, unknown>,
    };
    const project = await projectRepo.create(input);

    // Black-box → ingest yields null (no repo cloned); mint + start the scan
    // exactly as the ordinary external start path does.
    const codebaseVersion = await ingestForScan(project, { tenantId, userId: principal.uid });
    const scan = await scanRepo.create({
      projectId: project.id,
      codebaseVersionId: codebaseVersion ? codebaseVersion.id : null,
      temporalWorkflowId: null,
      status: 'pending',
    });
    const manifest = buildInjectionManifest(tenantId, principal.uid, 'anthropic');
    const started = await startScan(scan, project, codebaseVersion, manifest);

    // Audit linkage: engagement → roeHash → launch-grant id → scan → hosts. Never
    // the token value (only its row id, `grantId`). `at` is the run's startedAt.
    await getAuditTee().emit({
      type: 'launch.authorized',
      outcome: 'allow',
      tenantId,
      scanId: started.id,
      actor: 'mcp-connector',
      message: `black-box scan ${started.id} authorized for engagement ${engagementId}`,
      detail: { engagementId, roeHash, grantId: grant.tokenId, projectId: project.id, targetHosts: targetHosts(roe) },
    });

    return ok({ projectId: project.id, scanId: started.id, status: started.status });
  } catch (err) {
    return serverError(err);
  }
}
