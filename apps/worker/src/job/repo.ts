// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Repo materialization for the Cloud Run Job entrypoint (ADR-051, Phase 4).
 *
 * Two delivery modes:
 *  - Direct `docker run -v` — `SHOR_REPO_PATH` already points at a populated,
 *    writable repo. Use it as-is.
 *  - Cloud Run Job — the codebase snapshot lives in a GCS bucket mounted
 *    read-only at `/gcs`. We copy `/gcs/<prefix>` (prefix parsed from
 *    `SHOR_REPO_GCS_URI`) into the WRITABLE `SHOR_REPO_PATH`, because the
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

/** True if `p` exists and is a regular file. */
function fileExists(p: string): boolean {
	try {
		return fs.statSync(p).isFile();
	} catch {
		return false;
	}
}

/** Read a NUL-terminated string field from a tar header block. */
function tarField(block: Buffer, start: number, len: number): string {
	const slice = block.subarray(start, start + len);
	const nul = slice.indexOf(0);
	return slice.subarray(0, nul === -1 ? len : nul).toString("utf8");
}

/**
 * Extract an UNCOMPRESSED tar (`tar -cf`, as ingest's `tarWorkingTree` writes it)
 * into `dest`, in pure Node — no `tar` binary in the runtime image, and no npm
 * dependency (the repo's minimum-release-age policy blocks ad-hoc adds).
 *
 * Handles the entry kinds a source-tree archive contains: regular files (typeflag
 * '0'/NUL), directories ('5'), GNU long names ('L') and PAX path records ('x'),
 * plus the USTAR `prefix` field. Symlinks/devices and any path escaping `dest`
 * (absolute or `..`) are skipped — the agents only need the readable source tree.
 */
function extractTar(tarPath: string, dest: string): void {
	const buf = fs.readFileSync(tarPath);
	const BLOCK = 512;
	let off = 0;
	let override: string | null = null; // name from a preceding 'L'/'x' header
	while (off + BLOCK <= buf.length) {
		const header = buf.subarray(off, off + BLOCK);
		if (header.every((b) => b === 0)) break; // end-of-archive (zero block)
		const sizeOct = tarField(header, 124, 12).replace(/[^0-7]/g, "");
		const size = sizeOct ? Number.parseInt(sizeOct, 8) : 0;
		const type = String.fromCharCode(header[156] ?? 0);
		const dataOff = off + BLOCK;
		const content = buf.subarray(dataOff, dataOff + size);
		off = dataOff + Math.ceil(size / BLOCK) * BLOCK; // advance past padded data

		if (type === "L") {
			override = content.toString("utf8").replace(/\0+$/, ""); // GNU long name
			continue;
		}
		if (type === "x" || type === "g") {
			const m = content.toString("utf8").match(/\d+ path=([^\n]+)\n/); // PAX path
			if (m?.[1]) override = m[1];
			continue;
		}

		let name = override ?? tarField(header, 0, 100);
		const prefix = tarField(header, 345, 155);
		if (!override && prefix) name = `${prefix}/${name}`;
		override = null;

		const rel = path
			.normalize(name)
			.replace(/^(\.\/)+/, "")
			.replace(/^\/+/, "");
		if (!rel || rel === "." || rel.startsWith("..")) continue; // skip unsafe/empty
		const target = path.join(dest, rel);

		if (type === "5") {
			fs.mkdirSync(target, { recursive: true });
		} else if (type === "0" || type === "\0") {
			fs.mkdirSync(path.dirname(target), { recursive: true });
			fs.writeFileSync(target, content);
		}
		// symlinks ('2'), hardlinks ('1'), devices, etc. are intentionally ignored.
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
 * - If `SHOR_REPO_PATH` is already populated (direct `-v` case), it is used
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

	// The agent subprocess always runs with `repoPath` as its cwd and writes
	// deliverables under it. Create it up front so EVERY path below — black-box,
	// a missing GCS mount, an empty snapshot — degrades to "empty working tree"
	// instead of crashing the agent with ENOENT on a missing cwd (which the Agent
	// SDK surfaces as "executable … exists but failed to launch").
	await fs.promises.mkdir(repoPath, { recursive: true });

	// Black-box: no repo to copy; the pipeline runs target-only.
	if (!params.repoGcsUri) {
		logger.info("Black-box scan: no repo to materialize; running target-only", {
			scanId: params.scanId,
			repoPath,
		});
		return;
	}

	// Direct `docker run -v` case: repoPath is already a populated checkout.
	if (isPopulatedDir(repoPath)) {
		logger.info("Repo already populated; using mounted path as-is", {
			scanId: params.scanId,
			repoPath,
		});
		return;
	}

	if (!gcsMountExists()) {
		logger.warn("No GCS mount; running with an empty working tree", {
			scanId: params.scanId,
			repoPath,
			mount: GCS_MOUNT,
		});
		return;
	}

	const prefix = parseGcsPrefix(params.repoGcsUri);
	const source = prefix ? path.join(GCS_MOUNT, prefix) : GCS_MOUNT;

	if (!isPopulatedDir(source)) {
		logger.warn("GCS source prefix is empty or missing; running with an empty working tree", {
			scanId: params.scanId,
			source,
			repoGcsUri: params.repoGcsUri,
		});
		return;
	}

	// Ingest (apps/web .../ingest/git-source.ts) uploads the repo working tree as a
	// single `source.tar` object under the prefix. Extract it into repoPath so the
	// agents see real source files — NOT the tarball. Fall back to copying the
	// mounted tree for any non-tar snapshot layout.
	const tarPath = path.join(source, "source.tar");
	if (fileExists(tarPath)) {
		logger.info("Materializing repo: extracting source.tar from GCS mount", {
			scanId: params.scanId,
			source,
			repoPath,
		});
		extractTar(tarPath, repoPath);
	} else {
		logger.info("Materializing repo: copying tree from GCS mount", {
			scanId: params.scanId,
			source,
			repoPath,
		});
		await fs.promises.cp(source, repoPath, {
			recursive: true,
			force: true,
			errorOnExist: false,
		});
	}

	logger.info("Repo materialization complete", {
		scanId: params.scanId,
		repoPath,
	});
}
