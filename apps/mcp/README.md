# Shor MCP connector

Exposes Shor black-box scanning to Claude routines (claude.ai) and Claude Code as
an MCP server. It **re-implements no scanning** — it orchestrates Shor's existing
`/external/*` control plane server-to-server. Its reason to exist is one property:

> A routine can *ask* to start a scan, but only a **human** can *authorize* one.

## The three tools

| Tool | Wraps | Purpose |
|---|---|---|
| `start_blackbox_run` | `POST /external/launch` | Start a black-box scan. **Requires** a single-use launch token bound to the engagement + the signed RoE. Returns `{ projectId, scanId, status }`. |
| `get_run_progress` | `GET /external/scans/:id` | Read-only status: `{ status, progress, findingCount, startedAt, finishedAt }`. |
| `get_share_url` | `POST /external/projects/:id/share` | Mint/read the read-only guest link. Returns `{ shareUrl }` — the only client-facing output. |

There is **no** un-gated start tool, **no** white-box/repo tool, and **no**
delete/mutate-findings tool. That is deliberate.

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
| `MCP_BEARER_TOKEN` | Static bearer Claude clients present (empty ⇒ reject all). |
| `MCP_AUTH_MODE` | `bearer` (default) or `oauth` (see below). |
| `PORT` / `MCP_PORT` | Listen port (Cloud Run injects `PORT`). |

Control plane (`apps/web`), new:

| Env | Meaning |
|---|---|
| `SHOR_LAUNCH_MINT_TOKEN` | Operator-only secret for `POST /launch-tokens`. **Must differ** from `SHOR_ENGINE_TRIGGER_TOKEN`. Empty ⇒ minting disabled. |

Run migration `0007_launch_token.sql` (adds `launch_token` + `project.roe`).

## Auth: bearer now, OAuth-ready

The transport asks one question per request — "is this caller allowed?" —
answered by an `Authenticator` chosen by `MCP_AUTH_MODE` (`src/auth.ts`).

- **Claude Code / header-bearer clients:** `bearer` mode. Add the connector with
  `Authorization: Bearer <MCP_BEARER_TOKEN>`.
- **claude.ai web connector:** expects OAuth. `oauth` mode is a fail-closed seam:
  implement `oauthAuthenticator` (verify the access token) and serve
  `/.well-known/oauth-protected-resource`. **Nothing else changes** — tools, the
  Shor client, and the HTTP plumbing are auth-agnostic.

## Deployment reachability

The connector serves stateless Streamable-HTTP at `POST /mcp` (JSON responses),
plus an unauthenticated health probe at `GET /healthz`. Build with
`infra/docker/Dockerfile.mcp` and deploy as a Cloud Run **service**. For claude.ai
to reach it, ingress must be **public** (allow unauthenticated at the Cloud Run
layer — the connector does its own bearer/OAuth check) and not VPN-walled, so
Anthropic's egress can connect.

## Example (Claude Code)

```jsonc
// .mcp.json
{
  "mcpServers": {
    "shor": {
      "type": "http",
      "url": "https://shor-mcp-<hash>-uc.a.run.app/mcp",
      "headers": { "Authorization": "Bearer ${MCP_BEARER_TOKEN}" }
    }
  }
}
```

Then, once a human has approved and produced a token:

```
start_blackbox_run({
  engagementId: "eng-2026-014",
  authorizationToken: "<minted-by-approval-step>",
  roe: {
    version: 1,
    targetUrl: "https://app.example.com",
    allowedHosts: [{ host: "app.example.com", schemes: ["https"] }]
  }
})
```
