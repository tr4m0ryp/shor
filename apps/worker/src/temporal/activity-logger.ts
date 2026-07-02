// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { Context } from "@temporalio/activity";
import type { ActivityLogger } from "../types/activity-logger.js";

/**
 * ActivityLogger backed by Temporal's Context.current().log.
 * Must be called inside a running Temporal activity — throws otherwise.
 */
export class TemporalActivityLogger implements ActivityLogger {
	info(message: string, attrs?: Record<string, unknown>): void {
		Context.current().log.info(message, attrs ?? {});
	}

	warn(message: string, attrs?: Record<string, unknown>): void {
		Context.current().log.warn(message, attrs ?? {});
	}

	error(message: string, attrs?: Record<string, unknown>): void {
		Context.current().log.error(message, attrs ?? {});
	}
}

/**
 * Create an ActivityLogger. Must be called inside a Temporal activity.
 * Throws if called outside an activity context.
 */
export function createActivityLogger(): ActivityLogger {
	return new TemporalActivityLogger();
}
