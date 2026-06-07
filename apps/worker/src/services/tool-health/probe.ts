// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Tool-health preflight: confirm the security tools the agents rely on are
 * actually present and resolvable in the worker image.
 *
 * Why this exists: `{category}_vuln_coverage.json`'s `floorMet` is a TEXT check —
 * it asks whether the deliverable mentions a tool, NOT whether the tool runs. So
 * a tool that was never shipped looks identical to one the agent chose to skip.
 * That exact gap shipped before (trufflehog was in tools.lock but missing from
 * the build, so its skill silently no-op'd). This probes `command -v <tool>` for
 * every expected binary at scan start, writes `tool_health.json`, and logs LOUD
 * on any miss — so a broken image announces itself instead of degrading quietly.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fs, path } from "zx";
import type { ActivityLogger } from "../../types/activity-logger.js";

const execFileP = promisify(execFile);

/**
 * CLI security tools the image is expected to ship — the `KNOWN_SKILLS` universe
 * minus the non-binary skills (`authz-recipe` is a recipe doc, `generate-totp` a
 * helper script, `playwright` runs via MCP/npx). Keep in sync with the Dockerfile.
 */
export const EXPECTED_TOOLS: readonly string[] = [
	"arjun",
	"dnsx",
	"ffuf",
	"gau",
	"httpx",
	"katana",
	"kxss",
	"naabu",
	"nmap",
	"nuclei",
	"paramspider",
	"subfinder",
	"wafw00f",
	"waybackurls",
	"commix",
	"dalfox",
	"hydra",
	"interactsh-client",
	"jwt_tool",
	"nosqli",
	"sqlmap",
	"ssrfmap",
	"sstimap",
	"xsstrike",
	"gitleaks",
	"osv-scanner",
	"semgrep",
	"trivy",
	"trufflehog",
];

/** One tool's availability in the image. */
export interface ToolProbe {
	tool: string;
	available: boolean;
	/** Resolved PATH location, or null when not found. */
	path: string | null;
}

export interface ToolHealthSummary {
	total: number;
	available: number;
	missing: string[];
	probes: ToolProbe[];
}

/**
 * Parse the probe command's `tool<TAB>path|MISSING` lines into probes, in the
 * expected order (a tool absent from the output is treated as missing). Pure.
 */
export function parseProbeOutput(
	stdout: string,
	expected: readonly string[],
): ToolProbe[] {
	const resolved = new Map<string, string>();
	for (const line of stdout.split("\n")) {
		const tab = line.indexOf("\t");
		if (tab < 0) continue;
		const tool = line.slice(0, tab).trim();
		if (tool) resolved.set(tool, line.slice(tab + 1).trim());
	}
	return expected.map((tool) => {
		const value = resolved.get(tool);
		const available =
			value !== undefined && value !== "" && value !== "MISSING";
		return { tool, available, path: available ? (value as string) : null };
	});
}

/** Reduce probes to a summary with the missing list. Pure. */
export function summarizeToolHealth(probes: ToolProbe[]): ToolHealthSummary {
	const missing = probes.filter((p) => !p.available).map((p) => p.tool);
	return {
		total: probes.length,
		available: probes.length - missing.length,
		missing,
		probes,
	};
}

/** One-shot `command -v` loop over the expected tools (static, injection-safe names). */
function probeCommand(tools: readonly string[]): string {
	return `for t in ${tools.join(" ")}; do p=$(command -v "$t" 2>/dev/null); printf '%s\\t%s\\n' "$t" "\${p:-MISSING}"; done`;
}

/**
 * Probe tool availability and write `tool_health.json`. Best-effort: never throws.
 * A missing EXPECTED tool is logged at ERROR — that class of bug (a tool the
 * agents will call but that isn't in the image) must not pass silently again.
 */
export async function runToolHealthCheck(
	deliverablesPath: string,
	logger: ActivityLogger,
): Promise<ToolHealthSummary | null> {
	try {
		const { stdout } = await execFileP(
			"bash",
			["-c", probeCommand(EXPECTED_TOOLS)],
			{ timeout: 15_000, maxBuffer: 1 << 20 },
		);
		const summary = summarizeToolHealth(parseProbeOutput(stdout, EXPECTED_TOOLS));
		try {
			await fs.writeFile(
				path.join(deliverablesPath, "tool_health.json"),
				`${JSON.stringify(
					{
						generatedBy: "tool-health preflight",
						checkedAt: new Date().toISOString(),
						...summary,
					},
					null,
					2,
				)}\n`,
			);
		} catch {
			// artifact write is best-effort; the log below still surfaces the result
		}
		if (summary.missing.length > 0) {
			logger.error(
				`tool-health: ${summary.missing.length}/${summary.total} expected security tools MISSING from the image — their skills will silently no-op`,
				{ missing: summary.missing },
			);
		} else {
			logger.info(
				`tool-health: all ${summary.total} expected security tools present`,
			);
		}
		return summary;
	} catch (err) {
		logger.warn("tool-health: probe failed (continuing)", {
			error: err instanceof Error ? err.message : String(err),
		});
		return null;
	}
}
