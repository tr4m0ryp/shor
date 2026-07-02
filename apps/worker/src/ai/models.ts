// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Model tier definitions and resolution.
 *
 * Three tiers mapped to capability levels:
 * - "small"  (Flash — summarization, structured extraction)
 * - "medium" (Flash — tool use, general analysis)
 * - "large"  (Pro — deep reasoning, complex analysis)
 *
 * Users override via DEEPSEEK_SMALL_MODEL / DEEPSEEK_MEDIUM_MODEL / DEEPSEEK_LARGE_MODEL.
 * Legacy ANTHROPIC_SMALL/MEDIUM/LARGE_MODEL env vars still work as fallback.
 */

export type ModelTier = "small" | "medium" | "large";

const DEFAULT_MODELS: Readonly<Record<ModelTier, string>> = {
	small: "deepseek-v4-flash",
	medium: "deepseek-v4-flash",
	large: "deepseek-v4-pro",
};

/** Resolve a model tier to a concrete model ID. */
export function resolveModel(tier: ModelTier = "medium"): string {
	const deepseekVar = `DEEPSEEK_${tier.toUpperCase()}_MODEL`;
	const anthropicVar = `ANTHROPIC_${tier.toUpperCase()}_MODEL`;
	return (
		process.env[deepseekVar] ||
		process.env[anthropicVar] ||
		DEFAULT_MODELS[tier]
	);
}
