// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Console-backed ActivityLogger for the Cloud Run Job entrypoint.
 *
 * The job runs OUTSIDE any Temporal activity (ADR-051 inverts the self-
 * submitting worker), so it cannot use `createActivityLogger`, which requires a
 * live activity Context. Structured fields are emitted as JSON so Cloud Logging
 * picks them up as `jsonPayload`.
 */

import type { ActivityLogger } from "../types/activity-logger.js";

function emit(
	level: "info" | "warn" | "error",
	message: string,
	attrs?: Record<string, unknown>,
): void {
	const line =
		attrs && Object.keys(attrs).length > 0
			? `${message} ${JSON.stringify(attrs)}`
			: message;
	if (level === "error") console.error(line);
	else if (level === "warn") console.warn(line);
	else console.log(line);
}

/** ActivityLogger that writes to stdout/stderr (no Temporal context required). */
export class ConsoleActivityLogger implements ActivityLogger {
	info(message: string, attrs?: Record<string, unknown>): void {
		emit("info", message, attrs);
	}
	warn(message: string, attrs?: Record<string, unknown>): void {
		emit("warn", message, attrs);
	}
	error(message: string, attrs?: Record<string, unknown>): void {
		emit("error", message, attrs);
	}
}
