// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
