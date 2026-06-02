// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
