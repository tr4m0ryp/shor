// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Phase-level checkpointing so an interrupted scan can resume instead of redoing
 * the expensive early phases (recon / threat-model / vuln).
 *
 * After each pipeline phase completes, the per-scan deliverables directory is
 * snapshotted to a PERSISTENT location (`SHOR_CHECKPOINT_DIR`, a read-write GCS
 * volume mounted on the Job) and the phase is recorded in a `phases.json`
 * manifest. On a re-execution of the SAME `scanId`, the deliverables are restored
 * and the completed phases are skipped — the run continues from the first phase
 * that had not finished.
 *
 * Disabled gracefully: when `SHOR_CHECKPOINT_DIR` is unset (e.g. local/dev runs,
 * or before the volume is wired) every function is a no-op, so non-checkpointed
 * runs behave exactly as before. Every operation is best-effort and never throws
 * — a checkpoint I/O failure must not abort or fail a scan.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../../types/activity-logger.js";

/** Ordered pipeline phases that can be checkpointed/skipped (coarse, per-phase). */
export const CHECKPOINT_PHASES = [
	"prereq",
	"vuln",
	"screen",
	"exploit",
	"oracle",
] as const;
export type CheckpointPhase = (typeof CHECKPOINT_PHASES)[number];

/** The persistent checkpoint root (a mounted GCS volume), or undefined to disable. */
function checkpointRoot(): string | undefined {
	const dir = process.env.SHOR_CHECKPOINT_DIR?.trim();
	return dir ? dir : undefined;
}

/** Whether checkpointing is wired (the persistent volume is mounted). */
export function checkpointEnabled(): boolean {
	return checkpointRoot() !== undefined;
}

function scanRoot(root: string, scanId: string): string {
	// scanId is a UUID minted server-side; still sanitize so it can never escape.
	const safe = scanId.replace(/[^A-Za-z0-9._-]/g, "_");
	return path.join(root, "scans", safe);
}

function phasesFile(root: string, scanId: string): string {
	return path.join(scanRoot(root, scanId), "phases.json");
}

function deliverablesSnapshot(root: string, scanId: string): string {
	return path.join(scanRoot(root, scanId), "deliverables");
}

/**
 * The set of phases already completed for this scan (empty when checkpointing is
 * off or no manifest exists). Reading never throws — a malformed manifest is
 * treated as "nothing done".
 */
export function loadCompletedPhases(scanId: string): Set<CheckpointPhase> {
	const root = checkpointRoot();
	if (!root) return new Set();
	try {
		const file = phasesFile(root, scanId);
		if (!fs.existsSync(file)) return new Set();
		const parsed: unknown = JSON.parse(fs.readFileSync(file, "utf8"));
		if (!Array.isArray(parsed)) return new Set();
		const valid = new Set(CHECKPOINT_PHASES as readonly string[]);
		return new Set(
			parsed.filter(
				(p): p is CheckpointPhase => typeof p === "string" && valid.has(p),
			),
		);
	} catch {
		return new Set();
	}
}

/**
 * Restore a prior run's deliverables into the local deliverables dir and return
 * the completed-phase set, so the pipeline can skip what is already done. No-op
 * (returns empty) when checkpointing is off or no snapshot exists.
 */
export function restoreCheckpoint(
	scanId: string,
	deliverablesPath: string,
	logger: ActivityLogger,
): Set<CheckpointPhase> {
	const root = checkpointRoot();
	if (!root) return new Set();
	try {
		const snapshot = deliverablesSnapshot(root, scanId);
		const done = loadCompletedPhases(scanId);
		if (done.size === 0 || !fs.existsSync(snapshot)) return new Set();
		fs.mkdirSync(deliverablesPath, { recursive: true });
		// Copy snapshot → local deliverables (restore). force:true overwrites; we
		// trust the snapshot over any partial local state.
		fs.cpSync(snapshot, deliverablesPath, { recursive: true, force: true });
		logger.info("checkpoint: restored deliverables; resuming", {
			scanId,
			completedPhases: [...done],
		});
		return done;
	} catch (err) {
		logger.warn("checkpoint: restore failed; starting fresh", {
			scanId,
			error: err instanceof Error ? err.message : String(err),
		});
		return new Set();
	}
}

/**
 * Snapshot the current deliverables and mark `phase` complete. Best-effort: a
 * failure is logged and swallowed so it can never abort the scan.
 */
export function saveCheckpoint(
	scanId: string,
	phase: CheckpointPhase,
	deliverablesPath: string,
	logger: ActivityLogger,
): void {
	const root = checkpointRoot();
	if (!root) return;
	try {
		const snapshot = deliverablesSnapshot(root, scanId);
		fs.mkdirSync(snapshot, { recursive: true });
		if (fs.existsSync(deliverablesPath)) {
			fs.cpSync(deliverablesPath, snapshot, { recursive: true, force: true });
		}
		const done = loadCompletedPhases(scanId);
		done.add(phase);
		// Order the manifest by the canonical phase order for readability.
		const ordered = CHECKPOINT_PHASES.filter((p) => done.has(p));
		fs.writeFileSync(
			phasesFile(root, scanId),
			`${JSON.stringify(ordered, null, 2)}\n`,
		);
		logger.info("checkpoint: saved", { scanId, phase });
	} catch (err) {
		logger.warn("checkpoint: save failed; continuing without checkpoint", {
			scanId,
			phase,
			error: err instanceof Error ? err.message : String(err),
		});
	}
}
