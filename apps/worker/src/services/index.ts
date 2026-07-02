// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Services Module
 *
 * Exports DI container and service classes for agent execution.
 * Services are pure domain logic with no Temporal dependencies.
 */

export type { AgentExecutionInput } from "./agent-execution.js";
export { AgentExecutionService } from "./agent-execution.js";
export { ConfigLoaderService } from "./config-loader.js";
export type { ContainerDependencies } from "./container.js";
export {
	Container,
	getContainer,
	getOrCreateContainer,
	removeContainer,
} from "./container.js";
export { ExploitationCheckerService } from "./exploitation-checker.js";
export { loadPrompt } from "./prompt-manager.js";
export { assembleFinalReport, injectModelIntoReport } from "./reporting.js";
