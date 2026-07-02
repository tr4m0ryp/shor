// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Logger interface for services called from Temporal activities.
 * Keeps services Temporal-agnostic while providing structured logging.
 */
export interface ActivityLogger {
	info(message: string, attrs?: Record<string, unknown>): void;
	warn(message: string, attrs?: Record<string, unknown>): void;
	error(message: string, attrs?: Record<string, unknown>): void;
}
