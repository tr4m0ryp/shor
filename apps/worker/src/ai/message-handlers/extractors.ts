// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { AssistantMessage, ContentBlock } from "../types.js";

// Handles both array and string content formats from SDK
export function extractMessageContent(message: AssistantMessage): string {
	const messageContent = message.message;

	if (Array.isArray(messageContent.content)) {
		return messageContent.content
			.map((c: ContentBlock) => c.text || JSON.stringify(c))
			.join("\n");
	}

	return String(messageContent.content);
}

// Extracts only text content (no tool_use JSON) to avoid false positives in error detection
export function extractTextOnlyContent(message: AssistantMessage): string {
	const messageContent = message.message;

	if (Array.isArray(messageContent.content)) {
		return messageContent.content
			.filter((c: ContentBlock) => c.type === "text" || c.text)
			.map((c: ContentBlock) => c.text || "")
			.join("\n");
	}

	return String(messageContent.content);
}
