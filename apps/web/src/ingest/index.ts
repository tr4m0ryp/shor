// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Project ingest — public surface (LAUNCH-SPEC §4.2, Phase 4).
 *
 * White-box scans clone the project's selected repo (`owner/name`) with the
 * scanning user's GitHub PAT, store the source archive in GCS, and mint an
 * immutable `CodebaseVersion`. Black-box scans have no repo and no codebase
 * version (the pipeline runs against the target URL only).
 *
 * Entry point: `ingestForScan(project, options)` returns a `CodebaseVersion`
 * for white-box projects, or `null` for black-box ones.
 */

export { type GithubIngestInput, ingestGithub } from './git-source.js';
export { type IngestForScanOptions, ingestForScan } from './ingest.js';
