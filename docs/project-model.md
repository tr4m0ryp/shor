# Project model — companies, codebase versions, scan history

Aegis is **company/project-centric**: a tenant adds a codebase as a named
**Project** and we **retain its codebase versions and every past scan**, so they
can re-run over time and diff results. This is the durable spine the dashboard and
scan-to-scan diffs (ADR-010) hang off.

**Running example:** tenant **avelero** adds their DPP hosting tool → Project
**`ddphosting`**. Over time it accumulates codebase versions (uploaded zips or
GitHub pulls) and scans; all are kept and browsable.

## Entity model

```
Tenant (company)         e.g. avelero — owns projects, members (OAuth users)
  └─ Project             e.g. ddphosting — target URL(s) + connection mode + auth config
       ├─ CodebaseVersion   immutable snapshot: a GitHub pull of main OR an uploaded zip
       └─ Scan (Run)        a pipeline run bound to ONE codebase version + target URL
            ├─ Findings        ranked vulnerabilities  (output-schema.md)
            └─ AttackSurface   scenarios + kill chains + remediation prompts
```

`Tenant → Project → CodebaseVersion → Scan → {Findings, AttackSurface}`.

### Rough schema (informs the DB choice in the running cloud research)

```
tenant            { id, name, members[] (oauth subjects), created_at }
project           { id, tenant_id, name, target_urls[], connection_mode:
                    'github'|'upload', github_url?, default_branch?, auth_config,
                    created_at }
codebase_version  { id, project_id, version_no, source: 'github_pull'|'upload',
                    git_commit?, git_ref?, storage_uri (object store), size_bytes,
                    created_at, created_by }
scan              { id, project_id, codebase_version_id, target_url, status,
                    temporal_workflow_id, started_at, finished_at, summary{counts} }
finding           { id, scan_id, ... }      // ranked-vuln schema (output-schema.md)
attack_scenario   { id, scan_id, ... }      // scenario schema (output-schema.md)
```

Codebase **artifacts** (the actual code) live in per-tenant **object storage**
(GCS bucket, isolated by tenant); the DB holds metadata + a `storage_uri`. Keeps
the relational store lean and the (large, many-versioned) code out of it.

## Connection modes & the re-run flow

A Project is created in one of two modes:

- **GitHub connected** — store `github_url` + `default_branch` (usually `main`).
  A new run **pulls the latest `main`** into a fresh `CodebaseVersion`
  (`source: github_pull`, records `git_commit`). One click to re-scan.
- **Manual upload** — no repo connected; each new run requires the user to
  **upload a new version** (zip), creating a `CodebaseVersion` (`source: upload`).

```
New run on project P:
  if P.connection_mode == 'github':
      v = pull P.github_url @ P.default_branch  → new CodebaseVersion (commit pinned)
  else:
      v = uploaded zip (required)               → new CodebaseVersion
  scan = run pipeline against (v, P.target_url) → persist Findings + AttackSurface
```

Older `CodebaseVersion`s and `Scan`s are **never deleted by default** — they are
the history. A scan always pins the exact code it ran on (commit or uploaded
snapshot), so results are reproducible and attributable.

## Diffing (ties to ADR-010)

Scan-to-scan diffs are **scoped to a Project**: compare the latest scan against a
prior one to show *new / fixed / still-open* findings as the codebase evolves —
the core value of re-scanning a connected repo. Diffs are most meaningful between
consecutive `CodebaseVersion`s of the same Project.

## Storron lens

| | |
|---|---|
| **Baseline (storron)** | `cloneRepo(gitUrl)` shallow-clones (`--depth 1`) to `REPOS_DIR/<name>_<timestamp>`; zip upload similar. Each scan uses an ephemeral, per-scan workspace. **No Project entity, no codebase versioning, no retained scan history tied to a project.** Keys uploads by timestamp only. |
| **Improve** | Persist uploads as **immutable, versioned `CodebaseVersion`s under a named Project**; retain all scans; enable re-pull of `main`; move artifacts to per-tenant object storage for the cloud model. |
| **Combine** | Reuse storron's `uploads/git.ts` (`isGitUrl`, `cloneRepo`) and `uploads/zip.ts` as the **ingest step that produces a CodebaseVersion**, plus its per-scan workspace isolation as the run sandbox — but wrap them in the Project/version/history model above and store snapshots in GCS. |

## Open (reconcile when cloud research lands)

- Object-storage layout + per-tenant isolation (GCS bucket-per-tenant vs prefix).
- Retention/quotas per tenant (how many versions/scans to keep).
- GitHub **connection** mechanism for private repos (App vs PAT) — see research Q12.
- Whether large monorepos need full clone vs `--depth 1` for accurate diffs.
