// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { formatTimestamp } from "../../../utils/formatting.js";
import { filterJsonToolCalls } from "../../output-formatters.js";
import type {
	ApiErrorDetection,
	AssistantMessage,
	AssistantResult,
} from "../../types.js";
import {
	detectApiError,
	handleStructuredError,
} from "../api-error-detection.js";
import {
	extractMessageContent,
	extractTextOnlyContent,
} from "../extractors.js";

export function handleAssistantMessage(
	message: AssistantMessage,
	turnCount: number,
): AssistantResult {
	const content = extractMessageContent(message);
	const cleanedContent = filterJsonToolCalls(content);

	// Prefer structured error field from SDK, fall back to text-sniffing
	// Use text-only content for error detection to avoid false positives
	// from tool_use JSON (e.g. security reports containing "usage limit")
	let errorDetection: ApiErrorDetection;
	if (message.error) {
		errorDetection = handleStructuredError(message.error, content);
	} else {
		const textOnlyContent = extractTextOnlyContent(message);
		errorDetection = detectApiError(textOnlyContent);
	}

	const result: AssistantResult = {
		content,
		cleanedContent,
		apiErrorDetected: errorDetection.detected,
		logData: {
			turn: turnCount,
			content,
			timestamp: formatTimestamp(),
		},
	};

	// Only add shouldThrow if it exists (exactOptionalPropertyTypes compliance)
	if (errorDetection.shouldThrow) {
		result.shouldThrow = errorDetection.shouldThrow;
	}

	return result;
}
