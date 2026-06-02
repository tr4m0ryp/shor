-- Aegis initial schema (LAUNCH-SPEC §4.3, Cloud SQL for PostgreSQL, ADR-020).
--
-- Project model (ADR-015):
--   tenant -< project -< codebase_ver -< scan -< { finding, attack_surface }
--
-- Findings are stored as JSONB in storron's shape (ADR-033) with a GIN index;
-- scan-to-scan diffs/history come from pgMemento's JSONB write-delta log
-- (pgmemento.row_log) keyed on finding.fingerprint (ADR-031/032).
--
-- Idempotent: safe to apply once via db/migrate.ts. Does NOT need a live DB to
-- exist for `tsc`/`build`.

BEGIN;

-- gen_random_uuid() for server-side UUID PKs.
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ───────────────────────────── tenant ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenant (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_name      TEXT NOT NULL,
    idp_tenant_id TEXT NOT NULL UNIQUE,           -- Identity Platform tenant id
    plan          TEXT NOT NULL DEFAULT 'free',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ────────────────────────────── user ──────────────────────────────────────
-- "user" is a reserved word; quote it everywhere.
CREATE TABLE IF NOT EXISTS "user" (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    role       TEXT NOT NULL
        CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS user_tenant_idx ON "user" (tenant_id);

-- ─────────────────────────── provider_key ─────────────────────────────────
-- secret_ref → Secret Manager; NO key material is ever stored in the DB.
CREATE TABLE IF NOT EXISTS provider_key (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    provider   TEXT NOT NULL,
    secret_ref TEXT NOT NULL,                     -- aegis/<tenant>/<user>/<provider>
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id, provider)
);
CREATE INDEX IF NOT EXISTS provider_key_tenant_idx ON provider_key (tenant_id);

-- ───────────────────────────── project ────────────────────────────────────
CREATE TABLE IF NOT EXISTS project (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    target_url           TEXT NOT NULL,
    repo_installation_id TEXT,                    -- GitHub App installation id
    schedule             TEXT,                    -- cron string, NULL = on-demand
    auth_config          JSONB,                   -- target login/ROE config
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS project_tenant_idx ON project (tenant_id);

-- ──────────────────────────── codebase_ver ────────────────────────────────
-- Immutable snapshot minted per ingest.
CREATE TABLE IF NOT EXISTS codebase_ver (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('github', 'zip')),
    git_sha     TEXT,                             -- NULL for zip uploads
    gcs_prefix  TEXT NOT NULL,                    -- <tenantId>/<projectId>/<versionId>/
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS codebase_ver_project_idx ON codebase_ver (project_id);

-- ───────────────────────────────── scan ───────────────────────────────────
CREATE TABLE IF NOT EXISTS scan (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    codebase_ver_id      UUID NOT NULL REFERENCES codebase_ver(id) ON DELETE CASCADE,
    temporal_workflow_id TEXT,                    -- aegis-<scanId>; cancel = kill switch
    status               TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    started_at           TIMESTAMPTZ,
    finished_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS scan_project_idx ON scan (project_id);
CREATE INDEX IF NOT EXISTS scan_codebase_ver_idx ON scan (codebase_ver_id);

-- ──────────────────────────────── finding ─────────────────────────────────
-- data = §6.1 finding record (JSONB). GIN index on data; btree on (scan_id, fingerprint).
CREATE TABLE IF NOT EXISTS finding (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,                    -- stable diff key (ADR-031)
    data        JSONB NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'open', 'fixed', 'regressed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_data_gin ON finding USING GIN (data);
CREATE INDEX IF NOT EXISTS finding_scan_fingerprint_idx ON finding (scan_id, fingerprint);

-- ────────────────────────────── attack_surface ────────────────────────────
-- storron scenario / kill-chain shape (JSONB).
CREATE TABLE IF NOT EXISTS attack_surface (
    id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    data    JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS attack_surface_scan_idx ON attack_surface (scan_id);
CREATE INDEX IF NOT EXISTS attack_surface_data_gin ON attack_surface USING GIN (data);

-- ───────────────────── pgMemento delta log (ADR-032) ──────────────────────
-- pgMemento provides the JSONB write-delta log (pgmemento.row_log) used for
-- scan-to-scan finding diffs/history. Enable auditing on finding +
-- attack_surface only. The DO block degrades gracefully when the pgMemento
-- extension/schema is not installed (e.g. local dev), so this migration still
-- applies cleanly; in production, install pgMemento first.
DO $pgmemento$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_namespace WHERE nspname = 'pgmemento'
    ) THEN
        -- Initialize pgMemento audit infrastructure for the public schema and
        -- log existing rows, then start per-table auditing on our two tables.
        PERFORM pgmemento.create_schema_audit(
            'public'::text, FALSE, FALSE, ARRAY[]::text[],
            ARRAY['finding', 'attack_surface']::text[]
        );
        PERFORM pgmemento.create_table_audit('finding', 'public', 'pgmemento_audit_id', TRUE, TRUE, TRUE);
        PERFORM pgmemento.create_table_audit('attack_surface', 'public', 'pgmemento_audit_id', TRUE, TRUE, TRUE);
    ELSE
        RAISE NOTICE 'pgMemento not installed; skipping delta-log enablement for finding/attack_surface';
    END IF;
EXCEPTION WHEN OTHERS THEN
    -- Tolerate pgMemento API drift across versions: never fail the core schema.
    RAISE NOTICE 'pgMemento enablement skipped: %', SQLERRM;
END
$pgmemento$;

COMMIT;
