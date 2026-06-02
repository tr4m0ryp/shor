// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
