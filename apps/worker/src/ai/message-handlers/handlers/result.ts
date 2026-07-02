// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import type { ResultData, ResultMessage } from "../../types.js";

/** Final message of a query with duration / usage info. */
export function handleResultMessage(message: ResultMessage): ResultData {
	const usage = message.usage || {};
	const result: ResultData = {
		result: message.result || null,
		duration_ms: message.duration_ms || 0,
		permissionDenials: message.permission_denials?.length || 0,
	};
	if (typeof usage.input_tokens === "number")
		result.inputTokens = usage.input_tokens;
	if (typeof usage.output_tokens === "number")
		result.outputTokens = usage.output_tokens;
	if (typeof usage.cache_read_input_tokens === "number") {
		result.cacheReadInputTokens = usage.cache_read_input_tokens;
	}
	if (typeof usage.cache_creation_input_tokens === "number") {
		result.cacheCreationInputTokens = usage.cache_creation_input_tokens;
	}
	if (typeof message.num_turns === "number")
		result.numTurns = message.num_turns;

	// Only add subtype if it exists (exactOptionalPropertyTypes compliance)
	if (message.subtype) {
		result.subtype = message.subtype;
	}

	// Capture stop_reason for diagnostics (helps debug early stops, budget exceeded, etc.)
	if (message.stop_reason !== undefined) {
		result.stop_reason = message.stop_reason;
		if (message.stop_reason && message.stop_reason !== "end_turn") {
			console.log(`    Stop reason: ${message.stop_reason}`);
		}
	}

	if (message.structured_output !== undefined) {
		result.structuredOutput = message.structured_output;
	}

	return result;
}
