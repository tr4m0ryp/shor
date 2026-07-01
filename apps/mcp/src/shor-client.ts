/**
 * Server-to-server client for Shor's `/external/*` control plane.
 *
 * The connector re-implements NO scanning — it orchestrates the existing engine
 * endpoints. Every request carries the engine trigger token as a bearer; that
 * token is never logged and never returned in tool output. Non-2xx responses are
 * surfaced as `ShorApiError` carrying the status and the engine's error message
 * (which the engine has already scrubbed of secrets).
 */

import { getConfig } from './config.js';
import type { Roe } from './roe.js';

export class ShorApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ShorApiError';
  }
}

export interface LaunchResult {
  readonly projectId: string;
  readonly scanId: string;
  readonly status: string;
}

export interface RunProgress {
  readonly status: string;
  readonly progress: unknown;
  readonly findingCount: number;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
}

export interface ShareResult {
  readonly shareSlug: string;
  readonly shareUrl: string;
}

/** POST/GET a JSON endpoint on the control plane with the trigger bearer. */
async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const { shorBaseUrl, engineTriggerToken } = getConfig();
  const res = await fetch(`${shorBaseUrl}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${engineTriggerToken}`,
      ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  const parsed = text ? (JSON.parse(text) as Record<string, unknown>) : {};
  if (!res.ok) {
    const msg = typeof parsed.error === 'string' ? parsed.error : `HTTP ${res.status}`;
    throw new ShorApiError(res.status, msg);
  }
  return parsed as T;
}

export const shorClient = {
  /** Token-gated black-box launch. Forwards the signed RoE + launch token. */
  launch(input: { engagementId: string; authorizationToken: string; roe: Roe }): Promise<LaunchResult> {
    return call<LaunchResult>('POST', '/external/launch', input);
  },

  /** Read-only scan status snapshot. */
  getScan(scanId: string): Promise<RunProgress> {
    return call<RunProgress>('GET', `/external/scans/${encodeURIComponent(scanId)}`);
  },

  /** Mint/read the project's read-only guest link. */
  share(projectId: string): Promise<ShareResult> {
    return call<ShareResult>('POST', `/external/projects/${encodeURIComponent(projectId)}/share`);
  },
};
