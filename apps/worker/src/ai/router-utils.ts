// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Get the actual model name being used.
 * When using claude-code-router, the SDK reports its configured model (claude-sonnet)
 * but the actual model is determined by ROUTER_DEFAULT env var.
 */
export function getActualModelName(
	sdkReportedModel?: string,
): string | undefined {
	const routerBaseUrl = process.env.ANTHROPIC_BASE_URL;
	const routerDefault = process.env.ROUTER_DEFAULT;

	// If router mode is active and ROUTER_DEFAULT is set, use that
	if (routerBaseUrl && routerDefault) {
		// ROUTER_DEFAULT format: "provider,model" (e.g., "gemini,gemini-2.5-pro")
		const parts = routerDefault.split(",");
		if (parts.length >= 2) {
			return parts.slice(1).join(","); // Handle model names with commas
		}
	}

	// Fall back to SDK-reported model
	return sdkReportedModel;
}
