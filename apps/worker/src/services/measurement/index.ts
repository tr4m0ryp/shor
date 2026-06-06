// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Measurement harness (spec D2): quantify valid-vuln yield from a per-scan
 * deliverables directory so the team can validate the whole effort (and the
 * measure-first lean-prompts decision).
 *
 * READ-ONLY except for the single report it writes —
 * `<deliverablesPath>/measurement_report.json`. It reads the exploitation queues,
 * exploitation evidence, adversarial-screen / oracle adjudication, the gated-out
 * manual-review appendix, and best-effort audit metrics. It never mutates a
 * finding, re-runs an agent, or makes a network call.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";
import { computeReport } from "./compute.js";
import { readCostInputs } from "./cost.js";
import { loadFindings } from "./load-findings.js";
import { readOracleDispositions } from "./oracle-dispositions.js";
import type { MeasurementReport } from "./types.js";

export * from "./types.js";
export { computeReport } from "./compute.js";
export { loadFindings } from "./load-findings.js";
export type { LoadedFindings } from "./load-findings.js";
export { readOracleDispositions } from "./oracle-dispositions.js";
export { readCostInputs } from "./cost.js";

/** Filename of the report written into the deliverables directory. */
export const MEASUREMENT_REPORT_FILE = "measurement_report.json";

/**
 * Compute the measurement report from a deliverables dir WITHOUT writing it.
 * Useful for callers (and tests) that want the numbers without the side-effect.
 */
export function buildMeasurementReport(
	deliverablesPath: string,
	logger: ActivityLogger,
): MeasurementReport {
	const loaded = loadFindings(deliverablesPath, logger);
	const oracle = readOracleDispositions(deliverablesPath, logger);
	const cost = readCostInputs(deliverablesPath, logger);
	return computeReport(deliverablesPath, loaded, oracle, cost);
}

/**
 * Compute AND persist `<deliverablesPath>/measurement_report.json`, returning the
 * report. This is the lone write in the service; the inputs are never mutated. A
 * write failure is logged and swallowed — the in-memory report is still returned.
 */
export function generateMeasurementReport(
	deliverablesPath: string,
	logger: ActivityLogger,
): MeasurementReport {
	const report = buildMeasurementReport(deliverablesPath, logger);
	const file = path.join(deliverablesPath, MEASUREMENT_REPORT_FILE);
	try {
		fs.writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);
		logger.info("Wrote measurement report", {
			file,
			candidates: report.totals.candidates,
			confirmed: report.totals.confirmed,
			precision_proxy: report.precision.precision_proxy,
		});
	} catch (err) {
		logger.warn("Failed to write measurement report; returning in-memory copy", {
			file,
			error: err instanceof Error ? err.message : String(err),
		});
	}
	return report;
}
