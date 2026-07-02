// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * `GET /external/github/repos` — Sinas lists the tenant's connected repos.
 *
 * Reuses the SAME engine-side GitHub plumbing as the dashboard's `GET
 * /github/repos` (`getGithubToken` + `listUserRepos`) against the resolved
 * showcase/owner principal's stored token — GitHub lives engine-side, so Sinas
 * never holds the repo or the token. Unlike the dashboard read (which 404s when
 * no token is stored), this returns an empty list `{ repos: [] }` when nothing is
 * connected, so Sinas's repo picker degrades gracefully.
 */

import type { Principal } from '../../auth/index.js';
import { getGithubToken, listUserRepos } from '../../github/index.js';
import { ok, serverError } from '../dashboard/auth-util.js';
import type { ApiResponse } from '../router.js';

export async function listExternalRepos(principal: Principal): Promise<ApiResponse> {
  try {
    const pat = await getGithubToken(principal.tenantId, principal.uid);
    if (!pat) return ok({ repos: [] });
    const repos = await listUserRepos(pat);
    return ok({ repos });
  } catch (err) {
    return serverError(err);
  }
}
