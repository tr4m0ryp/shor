// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Scan parameters read from the Cloud Run Job environment (ADR-051).
 *
 * The orchestrator (`apps/web/.../scan-orchestrator.ts`) sets these on the Job:
 *   AEGIS_SCAN_ID, AEGIS_TARGET_URL, AEGIS_REPO_GCS_URI, AEGIS_PROVIDER_KEY_FILE.
 * The provider key is read from the file named by AEGIS_PROVIDER_KEY_FILE inside
 * the engine (sdk-env.ts) — never passed here as material.
 */

/** Resolved, validated scan parameters for one Job run. */
export interface ScanJobParams {
	scanId: string;
	targetUrl: string;
	/** GCS URI of the repo snapshot to scan (`gs://…`). */
	repoGcsUri: string;
	/**
	 * Local filesystem path to the prepared repo. Defaults to AEGIS_REPO_PATH or
	 * a workdir; the GCS snapshot is materialized here by ingest (Phase 4).
	 */
	repoPath: string;
	/** Optional pipeline config file path. */
	configPath?: string;
	/** Optional provider label (anthropic|openai|…) for logging/routing. */
	provider?: string;
}

function required(name: string): string {
	const value = process.env[name];
	if (!value || value.trim() === "") {
		throw new Error(`missing required env var: ${name}`);
	}
	return value;
}

function optional(name: string): string | undefined {
	const value = process.env[name];
	return value && value.trim() !== "" ? value : undefined;
}

/**
 * Read + validate the scan params from the environment. Throws on missing
 * required vars so a misconfigured Job fails fast (non-zero exit).
 */
export function readScanJobParams(): ScanJobParams {
	const scanId = required("AEGIS_SCAN_ID");
	const targetUrl = required("AEGIS_TARGET_URL");
	const repoGcsUri = required("AEGIS_REPO_GCS_URI");
	// AEGIS_REPO_PATH is the prepared repo location. On the Cloud Run Job it is
	// `/work/repo` (the writable target into which the GCS snapshot at `/gcs` is
	// materialized — see job/repo.ts). Absent/empty falls back to that default.
	const repoPath = optional("AEGIS_REPO_PATH") ?? "/work/repo";

	const params: ScanJobParams = {
		scanId,
		targetUrl,
		repoGcsUri,
		repoPath,
	};
	const configPath = optional("AEGIS_CONFIG_PATH");
	if (configPath) params.configPath = configPath;
	const provider = optional("AEGIS_PROVIDER");
	if (provider) params.provider = provider;
	return params;
}
