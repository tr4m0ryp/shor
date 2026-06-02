// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Public barrel for the error-handling service.
 *
 * Re-exports the PentestError class plus the helpers that activities,
 * services and the AI executor depend on. Internal-only helpers such as
 * classifyByErrorCode stay out of the public surface.
 */

export { classifyErrorForTemporal } from "./classify-for-temporal.js";
export { handlePromptError, PentestError } from "./pentest-error.js";
export { isRetryableError } from "./retry-patterns.js";
