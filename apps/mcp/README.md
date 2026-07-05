# Shor MCP connector

Exposes Shor black-box scanning to Claude routines (claude.ai) and Claude Code as
an MCP server. It **re-implements no scanning** — it orchestrates Shor's existing
`/external/*` control plane server-to-server. Its reason to exist is one property:

> A routine can *ask* to start a scan, but only a **human** can *authorize* one.

A thin **Python [FastMCP](https://gofastmcp.com) server** (mirrors the sibling
`enrichment-mcp`): Streamable HTTP at `/mcp`, ten tools, and a pluggable auth
layer. It owns no database and no scanning — it forwards to Shor's `/external/*`.

## The tools

Exactly one tool mutates by *starting* activity (`start_blackbox_run`, launch-token
gated); one *reduces* activity (`cancel_run`); the rest are read-only.

| Tool | Wraps | Purpose |
|---|---|---|
| `start_blackbox_run` | `POST /external/launch` | Start a black-box scan. **Requires** a single-use launch token bound to the engagement + the signed RoE. Returns `{ projectId, scanId, status }`. |
| `cancel_run` | `POST /external/scans/:id/cancel` | Stop a running scan (operator kill switch). Activity-reducing and idempotent → **no launch token needed**. Returns `{ scanId, status }`. |
| `list_active_runs` | `GET /external/scans` | Read-only list of in-flight scans (running + pending): `{ runs: [{ scanId, projectId, status, progress, startedAt }] }`. |
| `get_run_progress` | `GET /external/scans/:id` | Read-only status for one scan: `{ status, progress, findingCount, startedAt, finishedAt }`. |
| `get_findings` | `GET /external/scans/:id/findings` | Read-only finding records for one scan: `{ findings: [...] }`. |
| `get_report` | `GET /external/scans/:id/report` | Read-only finalized executive report: `{ report }` (`null` until finalized). |
| `get_attack_surface` | `GET /external/scans/:id/attack-surface` | Read-only attack-surface document (scenarios + kill chains): `{ attackSurface }`. |
| `list_projects` | `GET /external/projects` | Read-only list of the tenant's projects: `{ projects: [...] }`. |
| `get_scan_history` | `GET /external/projects/:id/scans` | Read-only list of one project's scans, newest first: `{ scans: [...] }`. |
| `get_share_url` | `POST /external/projects/:id/share` | Mint/read the read-only guest link. Returns `{ shareUrl }` — a client-facing output. |

There is **no** un-gated start tool, **no** white-box/repo tool, and **no**
delete/mutate-findings tool. Cancel is the sole non-start mutation, and it can
only ever *reduce* a run's blast radius, never widen scope. That is deliberate.

## The one human gate — and why a routine can't bypass it

```
  Telegram approval backend            Claude routine
  (holds SHOR_LAUNCH_MINT_TOKEN)       (holds NOTHING)
          │                                  │
          │ POST /launch-tokens              │ start_blackbox_run(engagementId,
          │  {engagementId, roeHash, ttl}    │   authorizationToken, roe)
          ▼                                  ▼
   ┌──────────────┐   token          ┌──────────────────┐
   │  launch_token │◀───────mint──────│  Shor MCP server │ (holds SHOR_ENGINE_TRIGGER_TOKEN)
   │   (Postgres)  │                  └───────┬──────────┘
   └──────┬───────┘                           │ POST /external/launch
          │  atomic validate + consume        ▼
          └──────────────────────────▶ Shor control plane ──▶ scan starts
                                       (default-deny RoE enforced)
```

1. **A human approves.** The operator's Telegram bot backend — the only holder of
   `SHOR_LAUNCH_MINT_TOKEN` — clicks **Approve**, which calls `POST /launch-tokens`
   with the engagement id, the **hash of the signed RoE**, and a TTL. Shor mints a
   single-use, scope-bound token and returns it to the approval backend.
2. **The routine consumes.** The approval backend hands that token to the routine
   (out of band). The routine calls `start_blackbox_run` with the token and the RoE.
3. **The gate fires in the control plane.** `POST /external/launch` re-hashes the
   presented RoE and, in a **single atomic UPDATE**, checks the token is unused,
   unexpired, and bound to this exact engagement + RoE — and marks it used. Any
   mismatch → `403`, nothing starts. No two concurrent calls can both pass (no TOCTOU).
4. **Scope is enforced twice.** The signed RoE is attached to the project, so
   Shor's own **default-deny** allowlist re-checks every network action. If the
   MCP's RoE and Shor's enforced RoE ever disagreed, default-deny wins — the run
   reaches nothing (the safe failure).

**Trust boundary (load-bearing):** the routine possesses no token and no way to
make one. The MCP server holds only `SHOR_ENGINE_TRIGGER_TOKEN` — enough to call
`/external/*`, **not** enough to mint (`/launch-tokens` demands the *different*
`SHOR_LAUNCH_MINT_TOKEN`). Minting is reachable **only** from the operator's
approval path. The human is therefore structurally in the loop; removing them
would require the mint secret, which the connector never has.

## Audit — "what authorized this scan?"

Every MCP-started scan writes one `launch.authorized` audit event linking
`engagementId → roeHash → launch-grant id → scanId → targetHosts → startedAt`. One
query traces any scan back to the signed agreement that authorized it. The token
**value** is never logged (only its row id as `grantId`).

## Configuration

MCP server (`apps/mcp`):

| Env | Meaning |
|---|---|
| `SHOR_BASE_URL` | Base URL of the Shor control plane (`/external/*`). |
| `SHOR_ENGINE_TRIGGER_TOKEN` | Bearer presented to `/external/*`. **Not** the mint secret. |
| `MCP_BEARER_TOKEN` | Static bearer for Claude Code (used only when `MCP_OAUTH_PROVIDER` is empty). |
| `MCP_OAUTH_PROVIDER` | Empty ⇒ static bearer; `workos` ⇒ WorkOS AuthKit OAuth (below). |
| `MCP_BASE_URL` | Public HTTPS URL of this connector (no `/mcp`); required for OAuth. |
| `WORKOS_AUTHKIT_DOMAIN` / `WORKOS_CLIENT_ID` / `WORKOS_CLIENT_SECRET` | WorkOS AuthKit app used in `workos` mode. |
| `PORT` / `MCP_PORT` | Listen port (Cloud Run injects `PORT`). |

Control plane (`apps/web`), new:

| Env | Meaning |
|---|---|
| `SHOR_LAUNCH_MINT_TOKEN` | Operator-only secret for `POST /launch-tokens`. **Must differ** from `SHOR_ENGINE_TRIGGER_TOKEN`. Empty ⇒ minting disabled. |

Run migration `0007_launch_token.sql` (adds `launch_token` + `project.roe`).

## Auth — bearer (Claude Code) or WorkOS OAuth (claude.ai)

Auth is isolated in `auth.py` (`build_auth`); switching modes is pure config.

- **Claude Code** — leave `MCP_OAUTH_PROVIDER` empty and set `MCP_BEARER_TOKEN`.
  The client sends it as an `Authorization: Bearer` header.
- **claude.ai web connector** — the web app can't send a bearer, so it uses OAuth.
  Set `MCP_OAUTH_PROVIDER=workos` with the four `WORKOS_*`/`MCP_BASE_URL` values.
  FastMCP's `WorkOSProvider` runs the **OAuth proxy**: it serves the OAuth + DCR
  endpoints to claude.ai itself and proxies the login to WorkOS AuthKit with one
  pre-registered client — **so it works even though AuthKit advertises no
  registration endpoint** (it doesn't). Switching to `workos` means the static
  bearer stops being accepted (one auth layer at a time).

**One manual WorkOS step:** add `<MCP_BASE_URL>/auth/callback` to the WorkOS
application's allowed **redirect URIs** (dashboard). Without it, the login fails
with a redirect-URI mismatch.

## Set up in claude.ai (OAuth)

1. Ensure `<MCP_BASE_URL>/auth/callback` is on the WorkOS app's redirect URIs.
2. claude.ai → **Settings → Connectors → Add custom connector** (needs a plan
   with custom connectors; org admins may need to enable them).
3. Paste the MCP URL: `<MCP_BASE_URL>/mcp`.
4. Complete the WorkOS login when prompted. The four tools then appear in chat.

## Set up in Claude Code (bearer)

Deploy with `MCP_OAUTH_PROVIDER` empty + `MCP_BEARER_TOKEN` set, then:

```
claude mcp add --transport http shor <MCP_BASE_URL>/mcp \
  --header "Authorization: Bearer <MCP_BEARER_TOKEN>"
```

## Deployment reachability

Serves Streamable HTTP at `/mcp`. Build with `infra/docker/Dockerfile.mcp`
(Python 3.12) and deploy as a Cloud Run **service** with `--allow-unauthenticated`
(the connector does its own auth; claude.ai carries no Google identity) and
`--max-instances 1` (the WorkOS proxy keeps OAuth state in memory). Ingress must
be public so Anthropic's egress can reach it.

## Calling `start_blackbox_run`

Once a human has approved and produced a token:

```json
{
  "engagement_id": "eng-2026-014",
  "authorization_token": "<minted-by-approval-step>",
  "roe": {
    "version": 1,
    "targetUrl": "https://app.example.com",
    "allowedHosts": [{ "host": "app.example.com", "schemes": ["https"] }]
  }
}
```
