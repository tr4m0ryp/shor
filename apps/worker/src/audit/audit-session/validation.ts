// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { PentestError } from "../../services/error-handling.js";
import { ErrorCode } from "../../types/errors.js";
import type { SessionMetadata } from "../utils.js";

/**
 * Validate required fields on a SessionMetadata input.
 *
 * Throws PentestError(CONFIG_VALIDATION_FAILED) if `id` or `webUrl` is missing.
 */
export function validateSessionMetadata(
	sessionMetadata: SessionMetadata,
): void {
	if (!sessionMetadata.id) {
		throw new PentestError(
			"sessionMetadata.id is required",
			"config",
			false,
			{ field: "sessionMetadata.id" },
			ErrorCode.CONFIG_VALIDATION_FAILED,
		);
	}

	if (!sessionMetadata.webUrl) {
		throw new PentestError(
			"sessionMetadata.webUrl is required",
			"config",
			false,
			{ field: "sessionMetadata.webUrl" },
			ErrorCode.CONFIG_VALIDATION_FAILED,
		);
	}
}
