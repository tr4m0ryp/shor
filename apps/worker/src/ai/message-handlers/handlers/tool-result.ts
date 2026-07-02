// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
