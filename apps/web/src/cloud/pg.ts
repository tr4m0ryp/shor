/**
 * Cloud SQL for PostgreSQL connection pool (ADR-020).
 *
 * Lazy singleton: the `pg.Pool` is constructed on first `getPool()` call, never
 * at import time, so `tsc`/`build` succeed without a live database. In Cloud Run
 * we connect over the Cloud SQL Auth Proxy unix socket
 * (`/cloudsql/<instanceConnectionName>`); locally we connect over TCP.
 */

import { type Pool, type PoolConfig, default as pg, type QueryResult, type QueryResultRow } from 'pg';
import { getConfig } from '../config.js';

let pool: Pool | undefined;

function buildPoolConfig(): PoolConfig {
  const { sql } = getConfig();

  const base: PoolConfig = {
    database: sql.database,
    user: sql.user,
    password: sql.password,
    max: sql.maxPoolSize,
  };

  // Prefer an explicit TCP host (local dev / proxy on localhost). Otherwise,
  // when an instance connection name is set, connect over the Cloud SQL Auth
  // Proxy unix socket that Cloud Run mounts at /cloudsql/<conn>.
  if (sql.host) {
    return {
      ...base,
      host: sql.host,
      port: sql.port,
      ...(sql.ssl ? { ssl: { rejectUnauthorized: false } } : {}),
    };
  }

  if (sql.instanceConnectionName) {
    return { ...base, host: `/cloudsql/${sql.instanceConnectionName}` };
  }

  // No connection target configured — default to localhost so construction
  // never throws; an actual query will surface the connection error.
  return { ...base, host: 'localhost', port: sql.port };
}

/** Lazily construct (and memoize) the shared connection pool. */
export function getPool(): Pool {
  if (!pool) {
    pool = new pg.Pool(buildPoolConfig());
  }
  return pool;
}

/** Run a parameterized query against the shared pool. */
export async function query<R extends QueryResultRow = QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<QueryResult<R>> {
  return getPool().query<R>(text, params as unknown[]);
}

/**
 * Run `fn` inside a single transaction, committing on success and rolling back
 * on any throw. The callback receives a dedicated client checked out from the
 * pool; do not use it after the function returns.
 */
export async function withTransaction<T>(fn: (client: import('pg').PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** Close the pool (graceful shutdown / tests). Safe to call when uninitialized. */
export async function closePool(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = undefined;
  }
}
