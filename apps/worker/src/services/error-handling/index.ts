// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
