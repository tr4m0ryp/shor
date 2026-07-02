// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Public surface of the git-manager module.
// Internal helpers (semaphore, change formatters, GitOperationResult type) stay
// private to this directory and are not re-exported here.

export { executeGitCommandWithRetry } from "./command.js";
export { createGitCheckpoint } from "./operations/checkpoint.js";
export { commitGitSuccess } from "./operations/commit.js";
export { rollbackGitWorkspace } from "./operations/rollback.js";
export { getGitCommitHash, isGitRepository } from "./repository.js";
