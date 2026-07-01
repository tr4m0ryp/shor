/**
 * MCP connector configuration — env-driven, no I/O at import.
 *
 * The connector is a thin, DB-less, mint-secret-less translator. It holds exactly
 * two secrets: the engine trigger token it presents to Shor's `/external/*` plane
 * (server-to-server), and the bearer it requires from Claude clients. It never
 * holds `SHOR_LAUNCH_MINT_TOKEN` — by construction it cannot mint launch tokens.
 *
 * Auth is one of two modes (`MCP_AUTH_MODE`):
 *   - `bearer` — a static bearer for Claude Code (the connector holds the token).
 *   - `oauth`  — WorkOS AuthKit as the authorization server, this connector as a
 *     pure OAuth 2.0 RESOURCE server (RFC 9728). It holds NO WorkOS client secret:
 *     claude.ai registers with AuthKit directly (DCR) and the connector only
 *     VERIFIES AuthKit-issued JWTs. Needs `WORKOS_AUTHKIT_DOMAIN` + `MCP_BASE_URL`.
 */

function env(name: string, fallback = ''): string {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

export interface McpConfig {
  /** Port the MCP HTTP transport listens on (Cloud Run sets $PORT → 8080). */
  readonly port: number;
  /** Base URL of the Shor control plane whose `/external/*` this wraps (`SHOR_BASE_URL`). */
  readonly shorBaseUrl: string;
  /** Bearer presented to `/external/*` server-to-server (`SHOR_ENGINE_TRIGGER_TOKEN`). */
  readonly engineTriggerToken: string;
  /**
   * Static bearer Claude clients must present to the MCP transport
   * (`MCP_BEARER_TOKEN`). This is the auth swap-point: the OAuth verifier plugs in
   * here without touching tool code. Empty = the transport rejects every request.
   */
  readonly bearerToken: string;
  /** Auth mode: `bearer` today; `oauth` selects the (stubbed) OAuth verifier. */
  readonly authMode: 'bearer' | 'oauth';
}

let cached: McpConfig | undefined;

export function getConfig(): McpConfig {
  if (cached) return cached;
  const authMode = env('MCP_AUTH_MODE', 'bearer') === 'oauth' ? 'oauth' : 'bearer';
  cached = {
    // Cloud Run injects PORT; fall back to MCP_PORT then 8080.
    port: envInt('PORT', envInt('MCP_PORT', 8080)),
    shorBaseUrl: env('SHOR_BASE_URL', 'http://localhost:3457').replace(/\/+$/, ''),
    engineTriggerToken: env('SHOR_ENGINE_TRIGGER_TOKEN'),
    bearerToken: env('MCP_BEARER_TOKEN'),
    authMode,
  };
  return cached;
}
