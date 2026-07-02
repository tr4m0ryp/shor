// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Identity → replay-auth bridge for the differential oracle (T1).
 *
 * Reads each scan identity's persisted Playwright storage-state cookies and builds
 * the auth headers used to replay an authz PoC AS that LOWER-privilege identity. The
 * PRIMARY identity (the privileged user the PoC was already captured under) is
 * excluded — it is the baseline, not a differential. An anonymous (no-auth) identity
 * is ALWAYS included as the privilege floor.
 *
 * ADR-050: cookie VALUES are read only to construct the replay request; they are
 * NEVER logged or surfaced. Fail-open everywhere: a missing/malformed state file
 * contributes no identity, never throws.
 */

import fs from 'node:fs';
import path from 'node:path';
import type { ActivityLogger } from '../../../types/activity-logger.js';

/** A lower-privilege identity to replay an authz PoC under. */
export interface ReplayIdentity {
  label: string;
  /** false ⇒ the anonymous (no-auth) floor; true ⇒ a real authenticated identity. */
  authenticated: boolean;
  headers: Record<string, string>;
}

/** The privileged baseline session dir — its cookies are already in the PoC. */
const PRIMARY_SESSION_DIR = 'identity-primary';

/** Anonymous floor: strip all auth (the executor removes the PoC's captured auth). */
const ANONYMOUS: ReplayIdentity = { label: 'anonymous', authenticated: false, headers: {} };

interface StorageCookie {
  name?: unknown;
  value?: unknown;
}

/** Build a `Cookie:` header from a Playwright storage-state file; "" on any failure. */
function cookieHeaderFrom(statePath: string): string {
  try {
    const doc = JSON.parse(fs.readFileSync(statePath, 'utf8')) as { cookies?: StorageCookie[] };
    const cookies = Array.isArray(doc.cookies) ? doc.cookies : [];
    const pairs = cookies
      .filter((c): c is { name: string; value: string } => typeof c.name === 'string' && typeof c.value === 'string')
      .map((c) => `${c.name}=${c.value}`);
    return pairs.join('; ');
  } catch {
    return '';
  }
}

/** Candidate locations of the per-identity session dirs, relative to deliverables. */
function identityDirCandidates(deliverablesPath: string): string[] {
  return [
    path.join(path.dirname(deliverablesPath), '.playwright-cli', 'identities'),
    path.join(deliverablesPath, '.playwright-cli', 'identities'),
  ];
}

/**
 * Load the differential replay identities: anonymous (always) + every NON-primary
 * identity session dir that has cookies. Directory-driven (no manifest/slug
 * coupling); the primary dir is excluded as the privileged baseline.
 */
export function loadDifferentialIdentities(deliverablesPath: string, logger: ActivityLogger): ReplayIdentity[] {
  const out: ReplayIdentity[] = [ANONYMOUS];
  for (const root of identityDirCandidates(deliverablesPath)) {
    let dirs: string[];
    try {
      dirs = fs.readdirSync(root);
    } catch {
      continue;
    }
    for (const dir of dirs) {
      if (dir === PRIMARY_SESSION_DIR) continue;
      const cookie = cookieHeaderFrom(path.join(root, dir, 'storage-state.json'));
      if (cookie === '') continue;
      out.push({ label: dir, authenticated: true, headers: { Cookie: cookie } });
    }
    if (out.length > 1) break;
  }
  // Log labels only — never the cookie values (ADR-050).
  logger.info('Oracle differential: loaded lower-privilege identities', {
    count: out.length,
    labels: out.map((i) => i.label),
  });
  return out;
}
