// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

export interface ToolCallInput {
	url?: string;
	element?: string;
	key?: string;
	fields?: unknown[];
	text?: string;
	action?: string;
	description?: string;
	command?: string;
	todos?: Array<{
		status: string;
		content: string;
	}>;
	[key: string]: unknown;
}

export interface ToolCall {
	name: string;
	input?: ToolCallInput;
}
