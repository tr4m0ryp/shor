// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Public surface of the agent-execution module.
 *
 * Re-exports `AgentExecutionService` and its input type so the rest of the
 * worker can keep importing from `./agent-execution.js`.
 */

export { AgentExecutionService } from "./service.js";
export type { AgentExecutionInput } from "./types.js";
