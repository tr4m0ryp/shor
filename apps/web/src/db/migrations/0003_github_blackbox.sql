-- GitHub PAT + black-box mode (replaces zip-upload + App-installation flow).
--
-- A project now records the selected repo's `owner/name` (`repo_full_name`) and
-- a `mode`:
--   whitebox → clone the selected repo via the user's PAT for code-aware scans
--   blackbox → no repo; the pipeline runs against just the target URL
-- Black-box scans have no CodebaseVersion, so `scan.codebase_ver_id` becomes
-- nullable. Idempotent: safe to apply once via db/migrate.ts.

BEGIN;

-- ───────────────────────────── project ────────────────────────────────────
-- Selected repo `owner/name` (NULL = black-box) + scan mode.
ALTER TABLE project ADD COLUMN IF NOT EXISTS repo_full_name TEXT;
ALTER TABLE project ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'blackbox';

-- ───────────────────────────────── scan ───────────────────────────────────
-- Black-box scans run with no codebase version.
ALTER TABLE scan ALTER COLUMN codebase_ver_id DROP NOT NULL;

COMMIT;
