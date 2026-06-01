# apps/ — runtime (ported + de-Tor'd after research)

- **web/** — dashboard, reused from storron `apps/web` (Runs, Findings, Attack
  Surface, History). Add: Targets (register site + repo + schedule) and
  scan-to-scan diff views.
- **worker/** — agent pipeline on the Claude Agent SDK + Temporal, ported from
  storron `apps/worker` minus all `tor-*`. Adds the preinstalled toolkit and
  the structured-findings output step.
- **cli/** — thin orchestrator (optional for single-tenant); the dashboard is the
  primary surface.

Single-tenant, self-hosted. Datastore (Postgres vs SQLite) pending research.
