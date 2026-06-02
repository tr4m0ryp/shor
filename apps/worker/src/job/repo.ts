// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Repo materialization for the Cloud Run Job entrypoint (ADR-051, Phase 4).
 *
 * Two delivery modes:
 *  - Direct `docker run -v` — `AEGIS_REPO_PATH` already points at a populated,
 *    writable repo. Use it as-is.
 *  - Cloud Run Job — the codebase snapshot lives in a GCS bucket mounted
 *    read-only at `/gcs`. We copy `/gcs/<prefix>` (prefix parsed from
 *    `AEGIS_REPO_GCS_URI`) into the WRITABLE `AEGIS_REPO_PATH`, because the
 *    pipeline writes deliverables under the repo (`.storron/deliverables/`).
 *
 * The image ships no `gcloud`; we copy with Node `fs.cp` over the FUSE mount.
 */

import fs from "node:fs";
import path from "node:path";
import type { ActivityLogger } from "../types/activity-logger.js";
import type { ScanJobParams } from "./env.js";

/** Default read-only mount point for the codebase GCS bucket on the Job. */
export const GCS_MOUNT = "/gcs";

/**
 * Parse the object prefix out of a `gs://bucket/prefix...` URI. Returns the
 * path after the bucket (no leading slash), or "" if the URI is bucket-only or
 * unparseable. The bucket name itself is dropped: the bucket is the mount root
 * (`/gcs`), so only the in-bucket prefix maps onto the mount.
 */
export function parseGcsPrefix(uri: string): string {
	const withoutScheme = uri.replace(/^gs:\/\//, "");
	const firstSlash = withoutScheme.indexOf("/");
	if (firstSlash === -1) return "";
	return withoutScheme
		.slice(firstSlash + 1)
		.replace(/^\/+/, "")
		.replace(/\/+$/, "");
}

/** True if `dir` exists and contains at least one entry. */
function isPopulatedDir(dir: string): boolean {
	try {
		return fs.statSync(dir).isDirectory() && fs.readdirSync(dir).length > 0;
	} catch {
		return false;
	}
}

/** True if a GCS bucket appears to be FUSE-mounted at `GCS_MOUNT`. */
function gcsMountExists(): boolean {
	try {
		return fs.statSync(GCS_MOUNT).isDirectory();
	} catch {
		return false;
	}
}

/**
 * Ensure `params.repoPath` holds a writable copy of the repo to scan.
 *
 * - If `AEGIS_REPO_PATH` is already populated (direct `-v` case), it is used
 *   as-is and returned unchanged.
 * - Otherwise, if a GCS mount exists at `/gcs`, the snapshot at
 *   `/gcs/<prefix>` is copied into `params.repoPath` (created, writable).
 * - If neither holds, the repoPath is left as-is for the caller to handle; a
 *   warning is logged so a misconfigured Job is visible in Cloud Logging.
 *
 * Idempotent: a second call over an already-populated target is a no-op.
 */
export async function materializeRepo(
	params: ScanJobParams,
	logger: ActivityLogger,
): Promise<void> {
	const { repoPath } = params;

	if (!params.repoGcsUri) {
		logger.info("Black-box scan: no repo to materialize; running target-only", {
			scanId: params.scanId,
		});
		return;
	}

	if (isPopulatedDir(repoPath)) {
		logger.info("Repo already populated; using mounted path as-is", {
			scanId: params.scanId,
			repoPath,
		});
		return;
	}

	if (!gcsMountExists()) {
		logger.warn("No GCS mount and repoPath is empty; nothing to materialize", {
			scanId: params.scanId,
			repoPath,
			mount: GCS_MOUNT,
		});
		return;
	}

	const prefix = parseGcsPrefix(params.repoGcsUri);
	const source = prefix ? path.join(GCS_MOUNT, prefix) : GCS_MOUNT;

	if (!isPopulatedDir(source)) {
		logger.warn("GCS source prefix is empty or missing; cannot materialize", {
			scanId: params.scanId,
			source,
			repoGcsUri: params.repoGcsUri,
		});
		return;
	}

	logger.info("Materializing repo from GCS mount", {
		scanId: params.scanId,
		source,
		repoPath,
	});

	await fs.promises.mkdir(repoPath, { recursive: true });
	// Copy the read-only mount into the writable target. `recursive` copies the
	// tree; deliverables are later written alongside under `.storron/`.
	await fs.promises.cp(source, repoPath, {
		recursive: true,
		force: true,
		errorOnExist: false,
	});

	logger.info("Repo materialization complete", {
		scanId: params.scanId,
		repoPath,
	});
}
