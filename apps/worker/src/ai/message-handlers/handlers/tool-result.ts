// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { formatTimestamp } from "../../../utils/formatting.js";
import type { ToolResultData, ToolResultMessage } from "../../types.js";

// Truncates long results for display (500 char limit), preserves full content for logging
export function handleToolResultMessage(
	message: ToolResultMessage,
): ToolResultData {
	const content = message.content;
	const contentStr =
		typeof content === "string" ? content : JSON.stringify(content, null, 2);

	const displayContent =
		contentStr.length > 500
			? `${contentStr.slice(0, 500)}...\n[Result truncated - ${contentStr.length} total chars]`
			: contentStr;

	return {
		content,
		displayContent,
		timestamp: formatTimestamp(),
	};
}
