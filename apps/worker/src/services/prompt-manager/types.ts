// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/** Variables interpolated into every prompt template. */
export interface PromptVariables {
	webUrl: string;
	repoPath: string;
	PLAYWRIGHT_SESSION?: string;
}

/** Resolved replacement for a single `@include(...)` directive. */
export interface IncludeReplacement {
	placeholder: string;
	content: string;
}
