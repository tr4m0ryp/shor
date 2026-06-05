// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Scan parameters read from the Cloud Run Job environment (ADR-051).
 *
 * The orchestrator (`apps/web/.../scan-orchestrator.ts`) sets these on the Job:
 *   SHOR_SCAN_ID, SHOR_TARGET_URL, SHOR_REPO_GCS_URI, SHOR_PROVIDER_KEY_FILE.
 * The provider key is read from the file named by SHOR_PROVIDER_KEY_FILE inside
 * the engine (sdk-env.ts) — never passed here as material.
 */

/** Resolved, validated scan parameters for one Job run. */
export interface ScanJobParams {
	scanId: string;
	targetUrl: string;
	/** GCS URI of the repo snapshot to scan (`gs://…`); absent for black-box runs. */
	repoGcsUri?: string;
	/**
	 * Local filesystem path to the prepared repo. Defaults to SHOR_REPO_PATH or
	 * a workdir; the GCS snapshot is materialized here by ingest (Phase 4).
	 */
	repoPath: string;
	/** Optional pipeline config file path. */
	configPath?: string;
	/** Optional pipeline config as raw YAML/JSON string (overrides configPath). */
	configYaml?: string;
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
	const scanId = required("SHOR_SCAN_ID");
	const targetUrl = required("SHOR_TARGET_URL");
	// Optional: black-box scans carry no repo. materializeRepo degrades to an
	// empty working tree and the pipeline runs against the target URL only.
	const repoGcsUri = optional("SHOR_REPO_GCS_URI");
	// SHOR_REPO_PATH is the prepared repo location. On the Cloud Run Job it is
	// `/work/repo` (the writable target into which the GCS snapshot at `/gcs` is
	// materialized — see job/repo.ts). Absent/empty falls back to that default.
	const repoPath = optional("SHOR_REPO_PATH") ?? "/work/repo";

	const params: ScanJobParams = {
		scanId,
		targetUrl,
		repoPath,
		...(repoGcsUri ? { repoGcsUri } : {}),
	};
	const configPath = optional("SHOR_CONFIG_PATH");
	if (configPath) params.configPath = configPath;
	const configYaml = optional("SHOR_CONFIG_YAML");
	if (configYaml) params.configYaml = configYaml;
	const provider = optional("SHOR_PROVIDER");
	if (provider) params.provider = provider;
	return params;
}
