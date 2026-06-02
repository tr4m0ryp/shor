// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

// Public surface of the git-manager module.
// Internal helpers (semaphore, change formatters, GitOperationResult type) stay
// private to this directory and are not re-exported here.

export { executeGitCommandWithRetry } from "./command.js";
export { createGitCheckpoint } from "./operations/checkpoint.js";
export { commitGitSuccess } from "./operations/commit.js";
export { rollbackGitWorkspace } from "./operations/rollback.js";
export { getGitCommitHash, isGitRepository } from "./repository.js";
