// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Run-health summary, emitted after the screen phase. Reads the per-category
 * coverage + screen-verdict artifacts, derives the two signals the run analysis
 * showed are silent killers — heavy screen fail-open and zero tool breadth — and
 * surfaces them LOUDLY: a `run_health.json` artifact plus ERROR-level alert logs.
 * A bad run announces itself instead of waiting to be hand-diagnosed from GCS.
 */

import { fs, path } from "zx";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { type CategoryScreenHealth, summarizeCategoryScreen } from "./screen.js";
import { type CategoryToolHealth, summarizeCategoryTools } from "./tools.js";

/** The seven analysis categories (kept parallel to screen-panel's SCREEN_CATEGORIES). */
const CATEGORIES = [
	"injection",
	"xss",
	"auth",
	"ssrf",
	"authz",
	"logic",
	"misconfig-web",
] as const;

/** Fail-open share at/above which a category's screen is flagged as barely-ran. */
const FAIL_OPEN_ALERT_RATE = 0.5;

export interface RunHealthReport {
	screen: CategoryScreenHealth[];
	tools: CategoryToolHealth[];
	alerts: string[];
}

async function readJson(
	deliverablesPath: string,
	file: string,
): Promise<unknown> {
	const p = path.join(deliverablesPath, file);
	try {
		return (await fs.pathExists(p))
			? JSON.parse(await fs.readFile(p, "utf8"))
			: undefined;
	} catch {
		return undefined;
	}
}

/** Derive the loud alert lines from the per-category summaries. Pure. */
export function buildAlerts(
	screen: readonly CategoryScreenHealth[],
	tools: readonly CategoryToolHealth[],
): string[] {
	const alerts: string[] = [];
	for (const s of screen) {
		if (s.totalVotes === 0) continue; // nothing screened (e.g. empty queue)
		if (s.failOpenRate >= FAIL_OPEN_ALERT_RATE) {
			alerts.push(
				`screen ${s.category}: ${Math.round(s.failOpenRate * 100)}% of votes fail-opened (${s.failOpen}/${s.totalVotes}) — adversarial validation barely ran`,
			);
		}
		if (s.unreachable > 0) {
			alerts.push(
				`screen ${s.category}: ${s.unreachable} vote(s) hit an unreachable surface — verify the service origin/targeting`,
			);
		}
	}
	for (const t of tools) {
		if (!t.toolEvidence) {
			alerts.push(
				`vuln ${t.category}: no evidence any expected tool ran (floor not met, 0 recommended) — findings are code-reading only`,
			);
		}
	}
	return alerts;
}

/**
 * Build the run-health report, write `run_health.json`, and log alerts loudly.
 * Best-effort: never throws. Safe to call whether the screen phase just ran or
 * was checkpoint-skipped (it reads the on-disk artifacts either way).
 */
export async function emitRunHealth(
	deliverablesPath: string,
	logger: ActivityLogger,
): Promise<RunHealthReport> {
	const screen: CategoryScreenHealth[] = [];
	const tools: CategoryToolHealth[] = [];
	for (const cat of CATEGORIES) {
		screen.push(
			summarizeCategoryScreen(
				cat,
				await readJson(deliverablesPath, `${cat}_screen_verdicts.json`),
			),
		);
		tools.push(
			summarizeCategoryTools(
				cat,
				await readJson(deliverablesPath, `${cat}_vuln_coverage.json`),
			),
		);
	}
	const alerts = buildAlerts(screen, tools);
	const report: RunHealthReport = { screen, tools, alerts };

	try {
		await fs.writeFile(
			path.join(deliverablesPath, "run_health.json"),
			`${JSON.stringify(
				{
					generatedBy: "run-health summary",
					checkedAt: new Date().toISOString(),
					...report,
				},
				null,
				2,
			)}\n`,
		);
	} catch (err) {
		logger.warn("run-health: failed to write run_health.json", {
			error: err instanceof Error ? err.message : String(err),
		});
	}

	if (alerts.length > 0) {
		logger.error(
			`run-health: ${alerts.length} alert(s) — this scan underperformed; see run_health.json`,
			{ alerts },
		);
	} else {
		logger.info(
			"run-health: no alerts — tool breadth and screen validation look healthy",
		);
	}
	return report;
}
