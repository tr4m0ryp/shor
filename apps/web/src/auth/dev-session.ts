/**
 * Env-gated dev session (DEV ONLY — `AEGIS_DEV_LOGIN`).
 *
 * Lets the dashboard log in and load real data against the database WITHOUT
 * standing up the full Identity Platform browser flow. When `AEGIS_DEV_LOGIN`
 * is true and `GET /auth/me` has no valid session, the route provisions a
 * seeded tenant + owner user, seeds one sample project, and mints a normal
 * session for that principal — reusing the unchanged `session.ts` machinery.
 *
 * Everything here is idempotent (find-or-create by stable natural keys) so it
 * is safe to call on every dev `/auth/me`. This path is STRICTLY additive and
 * flag-gated; it does NOT touch or weaken the normal auth path, and callers
 * MUST check `getConfig().devLogin` before invoking it (see `routes.ts`).
 */

import { projectRepo } from '../db/repositories/project.js';
import { tenantRepo } from '../db/repositories/tenant.js';
import { userRepo } from '../db/repositories/user.js';
import type { Project, Tenant, User } from '../domain/types.js';
import type { Principal } from './middleware.js';

/** Stable natural keys for the seeded dev identity (no secrets — local only). */
const DEV_TENANT_IDP_ID = 'dev';
const DEV_TENANT_ORG = 'dev';
const DEV_USER_EMAIL = 'dev@aegis.local';
const DEV_USER_ROLE = 'owner' as const;

/** Stable natural key for the seeded sample project (Targets list). */
const DEV_PROJECT_NAME = 'avelero';
const DEV_PROJECT_TARGET_URL = 'https://avelero.com';

/**
 * Idempotently provision the seeded dev tenant + owner user and return the
 * principal a session is minted for. Reuses existing rows when already present
 * (keyed by `idp_tenant_id='dev'` and `(tenant, email)='dev@aegis.local'`), so
 * repeated dev logins never duplicate rows.
 */
export async function ensureDevSession(): Promise<Principal> {
  const tenant = await ensureDevTenant();
  const user = await ensureDevUser(tenant.id);
  return { uid: user.id, tenantId: tenant.id, role: user.role, org: tenant.orgName };
}

/**
 * Idempotently seed one sample project for the dev tenant so the Targets list
 * is not empty on a fresh database. Matches on the stable project name within
 * the tenant; creates it only when absent.
 */
export async function seedDevProject(tenantId: string): Promise<Project> {
  const existing = await findDevProject(tenantId);
  if (existing) return existing;
  return projectRepo.create({
    tenantId,
    name: DEV_PROJECT_NAME,
    targetUrl: DEV_PROJECT_TARGET_URL,
    repoInstallationId: null,
    schedule: null,
    authConfig: null,
  });
}

/** Find-or-create the dev tenant by its stable IdP tenant id (`'dev'`). */
async function ensureDevTenant(): Promise<Tenant> {
  const existing = await tenantRepo.findByIdpTenantId(DEV_TENANT_IDP_ID);
  if (existing) return existing;
  return tenantRepo.create({ orgName: DEV_TENANT_ORG, idpTenantId: DEV_TENANT_IDP_ID, plan: 'free' });
}

/** Find-or-create the dev owner user by stable email within the dev tenant. */
async function ensureDevUser(tenantId: string): Promise<User> {
  const existing = await userRepo.findByEmail(tenantId, DEV_USER_EMAIL);
  if (existing) return existing;
  return userRepo.create({ tenantId, email: DEV_USER_EMAIL, role: DEV_USER_ROLE });
}

/** Locate the seeded sample project (by stable name) within the dev tenant. */
async function findDevProject(tenantId: string): Promise<Project | null> {
  const projects = await projectRepo.listByTenant(tenantId);
  return projects.find((p) => p.name === DEV_PROJECT_NAME) ?? null;
}
