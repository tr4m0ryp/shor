// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Select the pre-recon prompt filename. Pre-recon dispatch is clearnet-only,
 * so this always resolves to the clearnet template.
 *
 * Returns the bare filename (including `.txt`) so the caller can `path.join`
 * directly with the prompts directory. The `targetUrl` parameter is retained
 * for interface compatibility with callers.
 */
export function selectPreReconTemplate(_targetUrl: string): string {
	return "pre-recon-code.txt";
}
