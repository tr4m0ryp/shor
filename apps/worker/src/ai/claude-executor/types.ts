// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
