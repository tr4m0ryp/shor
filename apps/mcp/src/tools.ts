/**
 * The three Shor MCP tools. Each is a thin wrapper over `/external/*`; none
 * re-implements scanning. The connector deliberately exposes NOTHING else — no
 * un-gated start, no white-box/repo surface, no delete/mutate-findings tool.
 *
 *   start_blackbox_run  — the ONLY start path; structurally requires a launch token.
 *   list_active_runs    — read-only list of the tenant's in-flight scans.
 *   get_run_progress    — read-only status snapshot for one scan.
 *   get_share_url       — read-only guest link (the sole client-facing output).
 *
 * A launch token can only be minted by the operator's approval backend, so a
 * routine holding these tools still cannot start an unauthorized scan.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { roeSchema } from './roe.js';
import { ShorApiError, shorClient } from './shor-client.js';

/** Shape a successful tool result: human text + machine-readable structuredContent. */
function ok(structured: Record<string, unknown>) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(structured, null, 2) }],
    structuredContent: structured,
  };
}

/** Shape an error result. Engine messages are already secret-scrubbed; never echo inputs. */
function fail(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}

/** Run a client call, mapping `ShorApiError` (and anything else) to an error result. */
async function guard<T extends Record<string, unknown>>(fn: () => Promise<T>) {
  try {
    return ok(await fn());
  } catch (err) {
    if (err instanceof ShorApiError) return fail(`Shor rejected the request (${err.status}): ${err.message}`);
    return fail(err instanceof Error ? err.message : String(err));
  }
}

export function registerTools(server: McpServer): void {
  server.registerTool(
    'start_blackbox_run',
    {
      title: 'Start authorized black-box scan',
      description:
        'Start a black-box security scan. REQUIRES a single-use authorizationToken minted by a human approver ' +
        'for THIS engagement and THIS exact RoE; the run is rejected otherwise. The RoE is the signed DEFAULT-DENY ' +
        'allowlist the engine enforces on every network action. Returns { projectId, scanId, status }.',
      inputSchema: {
        engagementId: z.string().min(1).describe('The signed engagement this run belongs to.'),
        authorizationToken: z
          .string()
          .min(1)
          .describe('Single-use launch token from the human approval step. The routine cannot mint this.'),
        roe: roeSchema.describe('The signed DEFAULT-DENY Rules of Engagement (scope allowlist).'),
      },
    },
    async ({ engagementId, authorizationToken, roe }) =>
      guard(async () => {
        const r = await shorClient.launch({ engagementId, authorizationToken, roe });
        return { projectId: r.projectId, scanId: r.scanId, status: r.status };
      }),
  );

  server.registerTool(
    'get_run_progress',
    {
      title: 'Get scan progress',
      description: 'Read-only status of a scan: { status, progress, findingCount, startedAt, finishedAt }.',
      inputSchema: { scanId: z.string().min(1).describe('The scanId returned by start_blackbox_run.') },
    },
    async ({ scanId }) =>
      guard(async () => {
        const r = await shorClient.getScan(scanId);
        return {
          status: r.status,
          progress: r.progress,
          findingCount: r.findingCount,
          startedAt: r.startedAt,
          finishedAt: r.finishedAt,
        };
      }),
  );

  server.registerTool(
    'get_share_url',
    {
      title: 'Get read-only results link',
      description:
        'Mint (or read) the project’s read-only guest link — the only client-facing output of a run. ' +
        'Read-only with respect to scanning. Returns { shareUrl }.',
      inputSchema: { projectId: z.string().min(1).describe('The projectId returned by start_blackbox_run.') },
    },
    async ({ projectId }) =>
      guard(async () => {
        const r = await shorClient.share(projectId);
        return { shareUrl: r.shareUrl };
      }),
  );
}
