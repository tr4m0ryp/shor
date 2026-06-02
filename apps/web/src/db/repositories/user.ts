/**
 * User repository (LAUNCH-SPEC §4.3, ADR-044).
 *
 * Each user belongs to exactly one tenant. Every read/mutate is scoped by
 * `tenantId` so a tenant can never touch another tenant's users (row-level
 * scoping enforced in the method signatures).
 */

import { query } from '../../cloud/pg.js';
import type { NewUser, TenantId, User, UserId, UserRole } from '../../domain/types.js';
import { toUser, type UserRow } from './rows.js';

export const userRepo = {
  async create(input: NewUser): Promise<User> {
    const { rows } = await query<UserRow>(
      `INSERT INTO "user" (tenant_id, email, role)
			 VALUES ($1, $2, $3)
			 RETURNING *`,
      [input.tenantId, input.email, input.role],
    );
    return toUser(rows[0] as UserRow);
  },

  async findById(tenantId: TenantId, id: UserId): Promise<User | null> {
    const { rows } = await query<UserRow>(`SELECT * FROM "user" WHERE tenant_id = $1 AND id = $2`, [tenantId, id]);
    return rows[0] ? toUser(rows[0]) : null;
  },

  async findByEmail(tenantId: TenantId, email: string): Promise<User | null> {
    const { rows } = await query<UserRow>(`SELECT * FROM "user" WHERE tenant_id = $1 AND email = $2`, [
      tenantId,
      email,
    ]);
    return rows[0] ? toUser(rows[0]) : null;
  },

  async listByTenant(tenantId: TenantId): Promise<User[]> {
    const { rows } = await query<UserRow>(`SELECT * FROM "user" WHERE tenant_id = $1 ORDER BY created_at`, [tenantId]);
    return rows.map(toUser);
  },

  async updateRole(tenantId: TenantId, id: UserId, role: UserRole): Promise<User | null> {
    const { rows } = await query<UserRow>(
      `UPDATE "user" SET role = $3
			 WHERE tenant_id = $1 AND id = $2
			 RETURNING *`,
      [tenantId, id, role],
    );
    return rows[0] ? toUser(rows[0]) : null;
  },

  async delete(tenantId: TenantId, id: UserId): Promise<void> {
    await query(`DELETE FROM "user" WHERE tenant_id = $1 AND id = $2`, [tenantId, id]);
  },
};
