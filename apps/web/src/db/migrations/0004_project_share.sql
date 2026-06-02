-- Read-only project sharing via guest links.
--
-- A dashboard owner mints an opaque `share_slug` on a project; anyone holding
-- `/<...>?share=<slug>` can READ that one project + its scans/findings/
-- attack-surface/diff/progress with no authentication and no mutation. The slug
-- is the access key: it is globally unique (partial unique index, NULLs ignored)
-- and resolves to exactly one project. NULL = not shared. Idempotent.

BEGIN;

ALTER TABLE project ADD COLUMN IF NOT EXISTS share_slug TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS project_share_slug_idx ON project (share_slug) WHERE share_slug IS NOT NULL;

COMMIT;
