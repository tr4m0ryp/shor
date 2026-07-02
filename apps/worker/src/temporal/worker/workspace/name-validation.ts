// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/** Validates a workspace name (1-128 chars, alphanumeric/hyphen/underscore, alphanumeric start). */
export function isValidWorkspaceName(name: string): boolean {
	return /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(name);
}
