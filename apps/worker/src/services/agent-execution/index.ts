// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Public surface of the agent-execution module.
 *
 * Re-exports `AgentExecutionService` and its input type so the rest of the
 * worker can keep importing from `./agent-execution.js`.
 */

export { AgentExecutionService } from "./service.js";
export type { AgentExecutionInput } from "./types.js";
