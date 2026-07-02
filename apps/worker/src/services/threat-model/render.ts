// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Render a {@link ThreatModel} into the compact `{{THREAT_MODEL}}` summary that
 * gets interpolated into downstream agent prompts. The summary is deliberately
 * short — top threats by impact x likelihood, the distinct trust boundaries, and
 * the crown-jewel assets — so it frames discovery without bloating the prompt.
 */

import {
	type EntryPoint,
	sensitivityOrdinal,
	type Threat,
	type ThreatModel,
	threatScore,
} from "./schema.js";
import { truncate } from "./util.js";

const MAX_THREATS = 6;
const MAX_ASSETS = 6;
const MAX_BOUNDARIES = 8;

function renderThreatLine(threat: Threat): string {
	const head = `- ${threat.id} [impact=${threat.impact}, likelihood=${threat.likelihood}] ${
		truncate(threat.threat, 160) || "(unspecified threat)"
	}`;
	const facets = [`actor=${threat.actor}`];
	if (threat.surface) facets.push(`surface=${truncate(threat.surface, 80)}`);
	if (threat.asset) facets.push(`asset=${truncate(threat.asset, 80)}`);
	const evidence = threat.evidence
		? ` evidence: ${truncate(threat.evidence, 120)}`
		: "";
	return `${head} (${facets.join(", ")})${evidence}`;
}

function boundaryLabels(entryPoints: EntryPoint[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const ep of entryPoints) {
		const base = ep.trust_boundary
			? `${ep.entry_point || "(entry)"} @ ${ep.trust_boundary}`
			: ep.entry_point;
		if (!base) continue;
		const reaches = ep.reachable_assets.length
			? ` -> ${ep.reachable_assets.slice(0, 4).join(", ")}`
			: "";
		const label = `${base}${reaches}`;
		if (!seen.has(label)) {
			seen.add(label);
			out.push(label);
		}
	}
	return out;
}

/**
 * Produce the prompt-ready summary string. Always returns a non-empty string for
 * any model that has at least a system context, an asset, an entry point, or a
 * threat; falls back to a sentinel note for a fully empty model.
 */
export function renderThreatModel(model: ThreatModel): string {
	const lines: string[] = [];

	if (model.system_context) {
		lines.push(`System context: ${truncate(model.system_context, 280)}`);
	}

	const crown = model.assets
		.filter((a) => a.sensitivity === "critical" || a.sensitivity === "high")
		.sort((a, b) => sensitivityOrdinal(b.sensitivity) - sensitivityOrdinal(a.sensitivity));
	const assets = (crown.length > 0 ? crown : model.assets).slice(0, MAX_ASSETS);
	if (assets.length > 0) {
		lines.push("", "Crown-jewel assets (by sensitivity):");
		for (const a of assets) {
			const desc = a.description ? `: ${truncate(a.description, 120)}` : "";
			lines.push(`- ${a.asset || "(unnamed asset)"} [${a.sensitivity}]${desc}`);
		}
	}

	const boundaries = boundaryLabels(model.entry_points).slice(0, MAX_BOUNDARIES);
	if (boundaries.length > 0) {
		lines.push("", "Trust boundaries / entry points:");
		for (const label of boundaries) lines.push(`- ${label}`);
	}

	const top = [...model.threats]
		.sort((a, b) => threatScore(b) - threatScore(a))
		.slice(0, MAX_THREATS);
	if (top.length > 0) {
		lines.push("", "Top threats (priority = impact x likelihood):");
		for (const threat of top) lines.push(renderThreatLine(threat));
	}

	const text = lines.join("\n").trim();
	return text.length > 0 ? text : "Threat model produced but contained no entries.";
}
