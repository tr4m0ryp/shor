# Aegis — Project Notes for Claude

Aegis (brand name "Shor") is a multi-tenant web-security scanning platform:
- `apps/web` → the `aegis-web` Cloud Run **service** (dashboard + control-plane API; serves the static UI from `apps/web/src/public/`).
- `apps/worker` → the `aegis-scan-worker` Cloud Run **Job** that runs the per-scan agent pipeline.
- Postgres on Cloud SQL (`aegis-db`); migrations via the `aegis-migrate` Job.

Deploy/build specifics (image split, commands, GCP project) live in per-session memory — do not duplicate them here.

## Deferred work — do NOT improvise these; they land in their own sessions

### 1. Real authentication architecture (today's auth is a prototype placeholder)
The hosted dashboard runs with `AEGIS_DEV_LOGIN=true`. In that mode any session-less `GET /auth/me` auto-provisions a fixed dev tenant + owner user (`apps/web/src/auth/dev-session.ts`) and mints a normal session cookie — **there is no real login**. This is scaffolding, not the auth model.

- Treat dev-login as a shortcut to be **removed**, not extended. Do not build features that lean on it.
- A proper authentication architecture must be **designed and implemented deliberately** (the Identity Platform flow is partially wired in `apps/web/src/auth/*`). Keep auth code clean, explicit, and well-factored — no sloppy shortcuts layered on the dev hack.
- The dev path must stay **strictly flag-gated** and must never weaken or short-circuit the real auth path.

### 2. Guest share-access code is hardcoded on the server, not in this repo
A read-only public share already exists: an owner mints an opaque `share_slug` on a project, and the `/share/:slug/...` GET routes expose that one project's scans/findings/diff with no session (`apps/web/src/server/share.ts`; invariants documented at the top of that file).

The team's **guest-access code/credential** for viewing a project as a guest will be **hardcoded on the server itself (env/config), not committed to this codebase**. It gets wired up at the end, in a separate conversation. Do not bake a hardcoded guest code into the repo — leave a config seam for it and stop there.

## Conventions / gotchas
- **Dev-login must seed NO sample data.** Anything created on the session-less `/auth/me` path recreates itself on every page load — that is exactly why a deleted "avelero" demo project kept reappearing on the dashboard. `ensureDevSession` provisions only the tenant + user; it seeds no project.
