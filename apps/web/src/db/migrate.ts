/**
 * Simple forward-only migration runner.
 *
 * Applies every `migrations/*.sql` file in lexical order inside a transaction,
 * recording applied filenames in a `schema_migrations` table so re-runs are
 * idempotent. Each SQL file manages its own BEGIN/COMMIT for DDL that cannot run
 * in an outer transaction (e.g. CREATE EXTENSION) — the runner does not wrap an
 * extra transaction around the file body.
 *
 * Does NOT need to run live for `tsc`/`build`. Invoke with `pnpm migrate`
 * (compiled) once a database is reachable.
 */

import { access, readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closePool, getPool } from '../cloud/pg.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Resolve the migrations directory. After `pnpm build` the .sql files are copied
 * next to the compiled migrate.js (dist/db/migrations); when run from source via
 * tsx they sit beside the .ts (src/db/migrations). Prefer the co-located dir,
 * fall back to the src tree (dist/db -> ../../src/db/migrations) so both work.
 */
async function resolveMigrationsDir(): Promise<string> {
  const colocated = join(HERE, 'migrations');
  try {
    await access(colocated);
    return colocated;
  } catch {
    return join(HERE, '..', '..', 'src', 'db', 'migrations');
  }
}

async function ensureMigrationsTable(): Promise<void> {
  await getPool().query(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`);
}

async function appliedFilenames(): Promise<Set<string>> {
  const { rows } = await getPool().query<{ filename: string }>('SELECT filename FROM schema_migrations');
  return new Set(rows.map((r) => r.filename));
}

async function migrationFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir);
  return entries.filter((f) => f.endsWith('.sql')).sort();
}

/** Apply all pending migrations. Returns the filenames newly applied. */
export async function migrate(): Promise<string[]> {
  await ensureMigrationsTable();
  const dir = await resolveMigrationsDir();
  const done = await appliedFilenames();
  const files = await migrationFiles(dir);
  const applied: string[] = [];

  for (const file of files) {
    if (done.has(file)) continue;
    const sql = await readFile(join(dir, file), 'utf8');
    const pool = getPool();
    // The .sql file owns its transaction; record the migration separately so
    // a failed file leaves no partial schema_migrations row.
    await pool.query(sql);
    await pool.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
    applied.push(file);
    console.log(`[migrate] applied ${file}`);
  }

  if (applied.length === 0) {
    console.log('[migrate] no pending migrations');
  }
  return applied;
}

// Run directly: `node dist/db/migrate.js`.
if (import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => closePool())
    .then(() => process.exit(0))
    .catch((err: unknown) => {
      console.error('[migrate] failed:', err);
      void closePool().finally(() => process.exit(1));
    });
}
