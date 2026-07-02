// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Per-user GitHub integration — public surface.
 *
 * `token` stores/reads/deletes the caller's PAT (Secret Manager-backed). `api`
 * uses that PAT to resolve the authenticated user and list selectable repos
 * (owned incl. private + collaborator/org + forked + starred). White-box scans
 * clone a selected repo with the same PAT (see `ingest/git-source`).
 */

export { storeGithubToken, getGithubToken, deleteGithubToken } from './token.js';
export { type GithubUser, type GithubRepo, getGithubUser, listUserRepos } from './api.js';
