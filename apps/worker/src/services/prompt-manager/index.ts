// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

// Public surface of the prompt-manager module.
// Internal helpers (buildLoginInstructions, processIncludes, buildAuthContext,
// interpolateVariables, PromptVariables, IncludeReplacement) stay private to
// this directory and are not re-exported here.

export { loadPrompt } from "./loader.js";
export { selectPreReconTemplate } from "./template-selection.js";
