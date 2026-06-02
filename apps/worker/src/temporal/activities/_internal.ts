// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Internal helpers shared across activities/ subdirectory.
 *
 * Constants, error-truncation utilities, and session/container builders
 * used by agent dispatch, preflight, and audit-logging modules.
 */

import type { ApplicationFailure } from "@temporalio/activity";
import type { SessionMetadata } from "../../audit/utils.js";
import { DEFAULT_DELIVERABLES_SUBDIR } from "../../paths.js";
import type { ContainerConfig } from "../../types/config.js";
import type { ActivityInput } from "./types.js";

// Max lengths to prevent Temporal protobuf buffer overflow
export const MAX_ERROR_MESSAGE_LENGTH = 2000;
export const MAX_STACK_TRACE_LENGTH = 1000;

// Max retries for output validation errors (agent didn't save deliverables)
export const MAX_OUTPUT_VALIDATION_RETRIES = 3;

export const HEARTBEAT_INTERVAL_MS = 2000;

/**
 * Truncate error message to prevent buffer overflow in Temporal serialization.
 */
export function truncateErrorMessage(message: string): string {
	if (message.length <= MAX_ERROR_MESSAGE_LENGTH) {
		return message;
	}
	return `${message.slice(0, MAX_ERROR_MESSAGE_LENGTH - 20)}\n[truncated]`;
}

/**
 * Truncate stack trace on an ApplicationFailure to prevent buffer overflow.
 */
export function truncateStackTrace(failure: ApplicationFailure): void {
	if (failure.stack && failure.stack.length > MAX_STACK_TRACE_LENGTH) {
		failure.stack = `${failure.stack.slice(0, MAX_STACK_TRACE_LENGTH)}\n[stack truncated]`;
	}
}

/**
 * Build SessionMetadata from ActivityInput.
 */
export function buildSessionMetadata(input: ActivityInput): SessionMetadata {
	const { webUrl, repoPath, outputPath, sessionId } = input;
	return {
		id: sessionId,
		webUrl,
		repoPath,
		...(outputPath && { outputPath }),
	};
}

/**
 * Build ContainerConfig from ActivityInput, falling back to defaults.
 */
export function buildContainerConfig(input: ActivityInput): ContainerConfig {
	return {
		deliverablesSubdir: input.deliverablesSubdir ?? DEFAULT_DELIVERABLES_SUBDIR,
		auditDir: input.auditDir ?? "./workspaces",
		...(input.apiKey !== undefined && { apiKey: input.apiKey }),
		...(input.promptDir !== undefined && { promptDir: input.promptDir }),
		...(input.providerConfig !== undefined && {
			providerConfig: input.providerConfig,
		}),
	};
}
