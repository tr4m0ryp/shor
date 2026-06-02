/**
 * @aegis/web — cloud + data foundation public surface (Task 010).
 *
 * This is the shared substrate Phase 2-5 tasks import: env config, lazy cloud
 * client wrappers (Secret Manager, GCS, Cloud SQL, Temporal Cloud, Identity
 * Platform), the domain types, and tenant-scoped repositories. The HTTP server
 * and dashboard land in later phases.
 *
 * Nothing here touches the network at import time; all GCP/Temporal clients are
 * constructed lazily on first use.
 */

export * as cloud from './cloud/index.js';
export type {
  AegisConfig,
  CloudSqlConfig,
  GcpConfig,
  IdentityConfig,
  SecretsConfig,
  StorageConfig,
  TemporalConfig,
} from './config.js';
export { getConfig, resetConfig } from './config.js';
export { migrate } from './db/migrate.js';
export * as repositories from './db/repositories/index.js';
export * from './domain/types.js';
export * as secrets from './secrets/index.js';
