// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Render a `HistoricalSignal` into the compact `{{HISTORICAL_SEED}}` string.
 *
 * Output is a short, agent-facing brief: hot files worth re-examining first and
 * dependency CVEs worth confirming reachable. Returns `""` for an empty signal
 * so the prompt-assembly call-site (task 005) can fall back to the neutral
 * sentinel rather than emitting an empty section.
 */

import type { DepCve, HistoricalSignal, HotFile } from "./types.js";

function renderHotFile(hot: HotFile): string {
	const n = hot.commits.length;
	const plural = n === 1 ? "commit" : "commits";
	const latest = hot.commits[0]?.subject ?? "";
	const cves =
		hot.cves && hot.cves.length > 0 ? ` [${hot.cves.join(", ")}]` : "";
	const subject = latest ? ` — "${latest}"` : "";
	return `- ${hot.file} (${n} security ${plural})${cves}${subject}`;
}

function renderDepCve(dep: DepCve): string {
	const fix = dep.fixedVersion ? `, fixed in ${dep.fixedVersion}` : "";
	return `- ${dep.package}@${dep.version} — ${dep.id} [${dep.severity}]${fix}`;
}

/**
 * Render the seed string. Empty signal → `""`.
 */
export function renderHistoricalSeed(signal: HistoricalSignal): string {
	const sections: string[] = [];

	if (signal.hotFiles.length > 0) {
		sections.push(
			"Previously-patched hot files (this code was changed for a security " +
				"reason before — re-examine it first):\n" +
				signal.hotFiles.map(renderHotFile).join("\n"),
		);
	}

	if (signal.depCves.length > 0) {
		sections.push(
			"Known-vulnerable dependencies (confirm each CVE is still reachable in " +
				"this app before relying on it):\n" +
				signal.depCves.map(renderDepCve).join("\n"),
		);
	}

	return sections.join("\n\n");
}
