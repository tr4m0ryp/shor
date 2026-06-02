// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { formatTimestamp } from "../../../utils/formatting.js";
import type { ToolUseData, ToolUseMessage } from "../../types.js";

export function handleToolUseMessage(message: ToolUseMessage): ToolUseData {
	return {
		toolName: message.name,
		parameters: message.input || {},
		timestamp: formatTimestamp(),
	};
}
