// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Module-level registry mapping each `workflowId` to its `Container`.
 *
 * Containers are created lazily by `getOrCreateContainer` on first use and
 * removed by `removeContainer` when a workflow completes. `getContainer`
 * returns the existing instance without creating one - useful for lightweight
 * activities that should not bootstrap a workflow's container by accident.
 */

import type { SessionMetadata } from "../../audit/utils.js";
import type { ContainerConfig } from "../../types/config.js";
import { Container } from "./container-class.js";
import { DEFAULT_CONFIG } from "./types.js";

/**
 * Map of workflowId to Container instance.
 * Each workflow gets its own container scoped to its lifecycle.
 */
const containers = new Map<string, Container>();

/**
 * Get or create a Container for a workflow.
 *
 * If a container already exists for the workflowId, returns it.
 * Otherwise, creates a new container with the provided dependencies.
 *
 * @param workflowId - Unique workflow identifier
 * @param sessionMetadata - Session metadata for audit paths
 * @param config - Runtime configuration (defaults to OSS standalone config)
 * @returns Container instance for the workflow
 */
export function getOrCreateContainer(
	workflowId: string,
	sessionMetadata: SessionMetadata,
	config: ContainerConfig = DEFAULT_CONFIG,
): Container {
	let container = containers.get(workflowId);

	if (!container) {
		container = new Container({ sessionMetadata, config });
		containers.set(workflowId, container);
	}

	return container;
}

/**
 * Remove a Container when a workflow completes.
 *
 * Should be called in logWorkflowComplete to clean up resources.
 *
 * @param workflowId - Unique workflow identifier
 */
export function removeContainer(workflowId: string): void {
	const container = containers.get(workflowId);
	if (container) {
		container.closeTor();
		containers.delete(workflowId);
	}
}

/**
 * Get an existing Container for a workflow, if one exists.
 *
 * Unlike getOrCreateContainer, this does NOT create a new container.
 * Returns undefined if no container exists for the workflowId.
 *
 * Useful for lightweight activities that can benefit from an existing
 * container but don't need to create one.
 *
 * @param workflowId - Unique workflow identifier
 * @returns Container instance or undefined
 */
export function getContainer(workflowId: string): Container | undefined {
	return containers.get(workflowId);
}
