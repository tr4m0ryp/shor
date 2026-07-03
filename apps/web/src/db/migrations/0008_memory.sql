-- Learning-memory storage substrate (engine-proof-and-memory, T1/T3/F10/F13).
--
-- Enables pgvector on the Supabase Postgres and adds the four tables the
-- two-tier RAG "learning memory" needs:
--   finding_embedding — per-finding local tier (raw, RLS-isolated by tenant)
--   fp_memory         — refuted/demoted findings for next-scan auto-filter
--   global_pool       — the cross-tenant tier (T2, user chose raw pooling)
--   cve_registry      — public known-vuln reference data (OSV/GHSA/NVD)
--
-- Vector shape (T1/F13): HNSW index + `halfvec` (fp16) at 1024 dims. HNSW because
-- ingestion is append-heavy (IVFFlat needs retraining). halfvec_cosine_ops is the
-- correct operator class for a halfvec column (cosine distance `<=>`); m=16,
-- ef_construction=64 are pgvector defaults tuned for this corpus size. Tenant
-- isolation is RLS + a B-tree pre-filter; retrieval sets
-- `hnsw.iterative_scan = relaxed_order` per query (task 012) so the tenant filter
-- does not over-filter the HNSW candidate list — that GUC is a pgvector 0.8.0+
-- feature (Supabase ships 0.8.0) and is NOT set here.
--
-- RLS model: the tenant-scoped tables (finding_embedding, fp_memory) gate every
-- row on `app.tenant_id` / `app.project_id` session claims the repository layer
-- sets with `SET LOCAL` (see repositories/memory/context.ts). global_pool and
-- cve_registry are cross-tenant readable by design. FORCE ROW LEVEL SECURITY is
-- set so the policies bind even when the app connects as the table owner — with
-- the caveat that a BYPASSRLS/superuser role (e.g. Supabase `postgres`) still
-- bypasses RLS; the app must connect as a non-BYPASSRLS role for isolation to
-- actually enforce (flagged in context.ts).
--
-- Cross-tenant WRITES to global_pool stay flag-gated at the APP layer
-- (`pooling_enabled`, task 014) behind the T2 guardrails (mandatory secret scrub,
-- DPA/consent, red-team-extraction audit); this migration only provisions storage.
--
-- Idempotent: safe to re-apply. Requires the `vector` extension to be available
-- on the target Postgres (Supabase: enable in Database > Extensions).

BEGIN;

-- pgvector: halfvec type + HNSW access method. Available on Supabase (0.8.0).
CREATE EXTENSION IF NOT EXISTS vector;

-- ─────────────────────────── finding_embedding ────────────────────────────
-- Local tier: per-finding embeddings + structured columns for SQL pre-filter and
-- exact-identifier BM25. Vector A (vec_text) = the verbalized finding doc; Vector
-- B (vec_code) = the minimal vulnerable code block (T3). Both nullable so partial
-- embeddings are storable. scan_id is SET NULL on delete so learned memory
-- survives a scan deletion; tenant/project cascade (memory dies with its owner).
CREATE TABLE IF NOT EXISTS finding_embedding (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    scan_id       UUID REFERENCES scan(id) ON DELETE SET NULL,
    vec_code      halfvec(1024),
    vec_text      halfvec(1024),
    cwe           TEXT,
    vuln_class    TEXT,
    severity      TEXT,
    route         TEXT,
    source        TEXT,
    sink          TEXT,
    component_ver TEXT,                             -- component@version
    confidence    TEXT,                             -- mirrors FindingConfidence label
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_embedding_scope_idx
    ON finding_embedding (tenant_id, project_id, cwe);
CREATE INDEX IF NOT EXISTS finding_embedding_veccode_hnsw
    ON finding_embedding USING hnsw (vec_code halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX IF NOT EXISTS finding_embedding_vectext_hnsw
    ON finding_embedding USING hnsw (vec_text halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ───────────────────────────────── fp_memory ──────────────────────────────
-- Refuted / demoted findings, keyed by the stable fingerprint per project so a
-- confirmed false-positive auto-filters (demotes, never hard-deletes) on future
-- scans. Upsert-by-(tenant, project, fingerprint) mirrors finding's re-ingest.
CREATE TABLE IF NOT EXISTS fp_memory (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    project_id  UUID NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    reason      TEXT,
    vec_text    halfvec(1024),
    decision    TEXT NOT NULL DEFAULT 'refuted',    -- refuted | demoted | false_positive
    decided_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, project_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS fp_memory_scope_idx ON fp_memory (tenant_id, project_id);
CREATE INDEX IF NOT EXISTS fp_memory_vectext_hnsw
    ON fp_memory USING hnsw (vec_text halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ──────────────────────────────── global_pool ─────────────────────────────
-- Cross-tenant tier (T2). `kind` distinguishes a promoted abstraction, a redacted
-- exemplar, and a raw pooled finding. `k_anon_count` tracks how many tenants a
-- pooled item aggregates (k-anonymity floor). `source_tenant` is provenance only
-- and SET NULL on tenant delete. WRITES are flag-gated at the app layer
-- (`pooling_enabled`, task 014) — this table only provisions storage.
CREATE TABLE IF NOT EXISTS global_pool (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          TEXT NOT NULL CHECK (kind IN ('abstraction', 'exemplar', 'finding')),
    vec_code      halfvec(1024),
    vec_text      halfvec(1024),
    payload       JSONB NOT NULL,
    k_anon_count  INTEGER NOT NULL DEFAULT 1,
    source_tenant UUID REFERENCES tenant(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS global_pool_kind_idx ON global_pool (kind);
CREATE INDEX IF NOT EXISTS global_pool_veccode_hnsw
    ON global_pool USING hnsw (vec_code halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX IF NOT EXISTS global_pool_vectext_hnsw
    ON global_pool USING hnsw (vec_text halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ──────────────────────────────── cve_registry ────────────────────────────
-- Public known-vuln reference data (OSV.dev batch -> GHSA -> NVD). Cross-tenant
-- readable. A surrogate id + UNIQUE(cve_id, package) lets one CVE span several
-- affected packages (OSV shape) without losing the natural key.
CREATE TABLE IF NOT EXISTS cve_registry (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id         TEXT NOT NULL,
    package        TEXT,
    version_ranges JSONB,                           -- affected semver ranges
    cwe            TEXT,
    patch_diff     TEXT,
    vec_text       halfvec(1024),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, package)
);
CREATE INDEX IF NOT EXISTS cve_registry_package_idx ON cve_registry (package);
CREATE INDEX IF NOT EXISTS cve_registry_cve_idx ON cve_registry (cve_id);
CREATE INDEX IF NOT EXISTS cve_registry_vectext_hnsw
    ON cve_registry USING hnsw (vec_text halfvec_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ─────────────────────────────────── RLS ──────────────────────────────────
-- Enable + FORCE on all four (see header for the BYPASSRLS caveat). Policies are
-- (re)created idempotently via DROP IF EXISTS + CREATE (CREATE POLICY has no
-- IF NOT EXISTS form). Tenant-scoped tables gate on the app.* session claims;
-- NULLIF(...,'') guards against casting an empty/unset claim to uuid.

ALTER TABLE finding_embedding ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_embedding FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS finding_embedding_tenant_isolation ON finding_embedding;
CREATE POLICY finding_embedding_tenant_isolation ON finding_embedding
    USING (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        AND (
            NULLIF(current_setting('app.project_id', true), '') IS NULL
            OR project_id = NULLIF(current_setting('app.project_id', true), '')::uuid
        )
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        AND (
            NULLIF(current_setting('app.project_id', true), '') IS NULL
            OR project_id = NULLIF(current_setting('app.project_id', true), '')::uuid
        )
    );

ALTER TABLE fp_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE fp_memory FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS fp_memory_tenant_isolation ON fp_memory;
CREATE POLICY fp_memory_tenant_isolation ON fp_memory
    USING (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        AND (
            NULLIF(current_setting('app.project_id', true), '') IS NULL
            OR project_id = NULLIF(current_setting('app.project_id', true), '')::uuid
        )
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        AND (
            NULLIF(current_setting('app.project_id', true), '') IS NULL
            OR project_id = NULLIF(current_setting('app.project_id', true), '')::uuid
        )
    );

-- Cross-tenant readable/writable pool + registry (writes gated at the app layer).
ALTER TABLE global_pool ENABLE ROW LEVEL SECURITY;
ALTER TABLE global_pool FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS global_pool_cross_tenant ON global_pool;
CREATE POLICY global_pool_cross_tenant ON global_pool
    USING (true) WITH CHECK (true);

ALTER TABLE cve_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE cve_registry FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cve_registry_cross_tenant ON cve_registry;
CREATE POLICY cve_registry_cross_tenant ON cve_registry
    USING (true) WITH CHECK (true);

COMMIT;
