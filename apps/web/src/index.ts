/**
 * @shor/web — cloud + data foundation public surface (Task 010) plus the
 * dashboard HTTP server entry (Phase 3).
 *
 * This is the shared substrate Phase 2-5 tasks import: env config, lazy cloud
 * client wrappers (Secret Manager, GCS, Cloud SQL, Temporal Cloud, Identity
 * Platform), the domain types, tenant-scoped repositories, and the multi-tenant
 * auth surface. When run directly (`node dist/index.js`) it starts the
 * framework-less HTTP server; when imported it stays a side-effect-free barrel.
 *
 * Nothing here touches the network at import time; all GCP/Temporal clients are
 * constructed lazily on first use.
 */

import { fileURLToPath } from 'node:url';
import { startDashboard } from './server/index.js';

export * as auth from './auth/index.js';
export * as cloud from './cloud/index.js';
export type {
  ShorConfig,
  CloudSqlConfig,
  GcpConfig,
  IdentityConfig,
  SecretsConfig,
  SessionConfig,
  StorageConfig,
  TemporalConfig,
} from './config.js';
export { getConfig, resetConfig } from './config.js';
export { migrate } from './db/migrate.js';
export * as repositories from './db/repositories/index.js';
export * from './domain/types.js';
export * as findings from './findings/index.js';
export * as guardrails from './guardrails/index.js';
export * as ingest from './ingest/index.js';
export * as orchestration from './orchestration/index.js';
export { createDashboardServer, startDashboard } from './server/index.js';
export * as secrets from './secrets/index.js';

// Start the dashboard only when this module is the process entrypoint
// (`node dist/index.js`), never on import.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  startDashboard();
}
