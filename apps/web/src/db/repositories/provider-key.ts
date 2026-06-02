/**
 * ProviderKey repository (LAUNCH-SPEC §4.3, ADR-017).
 *
 * Maps a (tenant, user, provider) to a Secret Manager reference. NO key
 * material is stored here — only `secret_ref`. Tenant-scoped on every query.
 */

import { query } from '../../cloud/pg.js';
import type { NewProviderKey, Provider, ProviderKey, ProviderKeyId, TenantId, UserId } from '../../domain/types.js';
import { type ProviderKeyRow, toProviderKey } from './rows.js';

export const providerKeyRepo = {
  /** Upsert the secret ref for a (tenant,user,provider) triple. */
  async upsert(input: NewProviderKey): Promise<ProviderKey> {
    const { rows } = await query<ProviderKeyRow>(
      `INSERT INTO provider_key (tenant_id, user_id, provider, secret_ref)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, user_id, provider)
			 DO UPDATE SET secret_ref = EXCLUDED.secret_ref
			 RETURNING *`,
      [input.tenantId, input.userId, input.provider, input.secretRef],
    );
    return toProviderKey(rows[0] as ProviderKeyRow);
  },

  async findById(tenantId: TenantId, id: ProviderKeyId): Promise<ProviderKey | null> {
    const { rows } = await query<ProviderKeyRow>('SELECT * FROM provider_key WHERE tenant_id = $1 AND id = $2', [
      tenantId,
      id,
    ]);
    return rows[0] ? toProviderKey(rows[0]) : null;
  },

  async findForUserProvider(tenantId: TenantId, userId: UserId, provider: Provider): Promise<ProviderKey | null> {
    const { rows } = await query<ProviderKeyRow>(
      `SELECT * FROM provider_key
			 WHERE tenant_id = $1 AND user_id = $2 AND provider = $3`,
      [tenantId, userId, provider],
    );
    return rows[0] ? toProviderKey(rows[0]) : null;
  },

  async listByUser(tenantId: TenantId, userId: UserId): Promise<ProviderKey[]> {
    const { rows } = await query<ProviderKeyRow>(
      `SELECT * FROM provider_key
			 WHERE tenant_id = $1 AND user_id = $2
			 ORDER BY provider`,
      [tenantId, userId],
    );
    return rows.map(toProviderKey);
  },

  async delete(tenantId: TenantId, id: ProviderKeyId): Promise<void> {
    await query('DELETE FROM provider_key WHERE tenant_id = $1 AND id = $2', [tenantId, id]);
  },
};
