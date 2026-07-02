// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/** Public result type returned by runClaudePrompt and consumed by retry/orchestration layers. */
export interface ClaudePromptResult {
	result?: string | null | undefined;
	success: boolean;
	duration: number;
	turns?: number | undefined;
	inputTokens?: number | undefined;
	outputTokens?: number | undefined;
	cacheReadInputTokens?: number | undefined;
	cacheCreationInputTokens?: number | undefined;
	model?: string | undefined;
	apiErrorDetected?: boolean | undefined;
	error?: string | undefined;
	errorType?: string | undefined;
	prompt?: string | undefined;
	retryable?: boolean | undefined;
	structuredOutput?: unknown;
}

declare global {
	var STORRON_DISABLE_LOADER: boolean | undefined;
}
