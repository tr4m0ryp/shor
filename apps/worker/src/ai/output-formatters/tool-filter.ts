// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { ToolCall, ToolCallInput } from "./types.js";

/** Extract domain from URL for display. */
function extractDomain(url: string): string {
	try {
		const urlObj = new URL(url);
		return urlObj.hostname || url.slice(0, 30);
	} catch {
		return url.slice(0, 30);
	}
}

/** Format playwright-cli commands into clean progress indicators. */
function formatBrowserAction(command: string): string | null {
	// Extract subcommand after optional session flag (e.g., "playwright-cli -s=session1 navigate https://example.com")
	const match = command.match(
		/playwright-cli\s+(?:-s=\S+\s+)?(\S+)(?:\s+(.*))?/,
	);
	if (!match) return null;

	const subcommand = match[1];
	const args = match[2] || "";

	switch (subcommand) {
		case "open":
		case "goto": {
			const domain = args.trim() ? extractDomain(args.trim()) : "";
			return domain ? `🌐 Navigating to ${domain}` : "🌐 Opening browser";
		}
		case "go-back":
			return "⬅️ Going back";
		case "go-forward":
			return "➡️ Going forward";
		case "reload":
			return "🔄 Reloading page";
		case "click":
		case "dblclick":
			return `🖱️ Clicking ${(args || "element").slice(0, 25)}`;
		case "hover":
			return `👆 Hovering over ${(args || "element").slice(0, 20)}`;
		case "type":
			return `⌨️ Typing ${(args || "text").slice(0, 20)}`;
		case "press":
		case "keydown":
		case "keyup":
			return `⌨️ Pressing ${args || "key"}`;
		case "fill":
			return `📝 Filling ${(args || "field").slice(0, 25)}`;
		case "select":
			return "📋 Selecting dropdown option";
		case "check":
		case "uncheck":
			return `☑️ ${subcommand === "check" ? "Checking" : "Unchecking"} ${(args || "element").slice(0, 20)}`;
		case "upload":
			return "📁 Uploading file";
		case "drag":
			return "🖱️ Dragging element";
		case "snapshot":
			return "📸 Taking page snapshot";
		case "screenshot":
			return "📸 Taking screenshot";
		case "eval":
		case "run-code":
			return "🔍 Running JavaScript analysis";
		case "console":
			return "📜 Checking console logs";
		case "network":
			return "🌐 Analyzing network traffic";
		case "tab-list":
		case "tab-new":
		case "tab-close":
		case "tab-select":
			return `🗂️ ${subcommand.replace("tab-", "")} browser tab`;
		case "dialog-accept":
			return "💬 Accepting dialog";
		case "dialog-dismiss":
			return "💬 Dismissing dialog";
		case "pdf":
			return "📄 Saving page as PDF";
		case "resize":
			return `🖥️ Resizing browser ${args || ""}`.trim();
		default:
			return `🌐 Browser: ${subcommand}`;
	}
}

/** Summarize TodoWrite updates into clean progress indicators. */
function summarizeTodoUpdate(input: ToolCallInput | undefined): string | null {
	if (!input?.todos || !Array.isArray(input.todos)) {
		return null;
	}

	const todos = input.todos;
	const completed = todos.filter((t) => t.status === "completed");
	const inProgress = todos.filter((t) => t.status === "in_progress");

	// Show recently completed tasks
	const recent = completed.at(-1);
	if (recent) {
		return `✅ ${recent.content}`;
	}

	// Show current in-progress task
	const current = inProgress.at(0);
	if (current) {
		return `🔄 ${current.content}`;
	}

	return null;
}

/** Filter out JSON tool calls from content, with special handling for Task calls. */
export function filterJsonToolCalls(
	content: string | null | undefined,
): string {
	if (!content || typeof content !== "string") {
		return content || "";
	}

	const lines = content.split("\n");
	const processedLines: string[] = [];

	for (const line of lines) {
		const trimmed = line.trim();

		// Skip empty lines
		if (trimmed === "") {
			continue;
		}

		// Check if this is a JSON tool call
		if (trimmed.startsWith('{"type":"tool_use"')) {
			try {
				const toolCall = JSON.parse(trimmed) as ToolCall;

				// Special handling for Task tool calls
				if (toolCall.name === "Task") {
					const description = toolCall.input?.description || "analysis agent";
					processedLines.push(`🚀 Launching ${description}`);
					continue;
				}

				// Special handling for TodoWrite tool calls
				if (toolCall.name === "TodoWrite") {
					const summary = summarizeTodoUpdate(toolCall.input);
					if (summary) {
						processedLines.push(summary);
					}
					continue;
				}

				// Special handling for browser tool calls (playwright-cli via Bash)
				if (toolCall.name === "Bash") {
					const command = toolCall.input?.command || "";
					if (command.includes("playwright-cli")) {
						const browserAction = formatBrowserAction(command);
						if (browserAction) {
							processedLines.push(browserAction);
						}
					}
				}
			} catch {
				// If JSON parsing fails, treat as regular text
				processedLines.push(line);
			}
		} else {
			// Keep non-JSON lines (assistant text)
			processedLines.push(line);
		}
	}

	return processedLines.join("\n");
}
