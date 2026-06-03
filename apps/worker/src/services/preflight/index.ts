// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Preflight Validation Service
 *
 * Runs fast checks before any agent execution begins.
 * Catches configuration and credential problems early, avoiding
 * mid-pipeline failures.
 *
 * Checks run sequentially, fastest first:
 * 1. Repository path exists and contains .git
 * 2. Config file parses and validates (if provided)
 * 3. Tooling discovery: every expected skill is discoverable + tool binaries on PATH
 * 4. Credentials validate via Claude Agent SDK query (API key, OAuth, Bedrock, Vertex AI, or router mode)
 * 5. Target URL is reachable from the container (DNS + HTTP)
 */

import type { ActivityLogger } from "../../types/activity-logger.js";
import { ok, type Result } from "../../types/result.js";
import type { PentestError } from "../error-handling.js";
import { validateCredentials } from "./auth/validate.js";
import { validateConfig } from "./config-validation.js";
import { validateRepo } from "./repo-validation.js";
import { validateToolingDiscovery } from "./tooling-discovery.js";
import { validateTargetUrl } from "./url-validation.js";

/**
 * Run all preflight checks sequentially (cheapest first).
 *
 * 1. Repository path exists and contains .git
 * 2. Config file parses and validates (if configPath provided)
 * 3. Tooling discovery: expected skills discoverable + tool binaries on PATH
 * 4. Credentials validate (API key, OAuth, or router mode)
 * 5. Target URL is reachable from the container
 *
 * Returns on first failure.
 */
export async function runPreflightChecks(
	targetUrl: string,
	repoPath: string,
	configPath: string | undefined,
	logger: ActivityLogger,
	skipGitCheck?: boolean,
	apiKey?: string,
	providerConfig?: import("../../types/config.js").ProviderConfig,
): Promise<Result<void, PentestError>> {
	// 1. Repository check (free — filesystem only)
	const repoResult = await validateRepo(repoPath, logger, skipGitCheck);
	if (!repoResult.ok) {
		return repoResult;
	}

	// 2. Config check (free — filesystem + CPU)
	if (configPath) {
		const configResult = await validateConfig(configPath, logger);
		if (!configResult.ok) {
			return configResult;
		}
	}

	// 3. Tooling discovery (free — filesystem + PATH only). Runs before the
	//    network checks: a missing skill/binary makes the scan useless, so fail
	//    fast in the image (loud warning only in a local/dev checkout).
	const toolingResult = await validateToolingDiscovery(logger);
	if (!toolingResult.ok) {
		return toolingResult;
	}

	// 4. Credential check (cheap — 1 SDK round-trip, skipped when providerConfig present)
	const credResult = await validateCredentials(logger, apiKey, providerConfig);
	if (!credResult.ok) {
		return credResult;
	}

	// 5. Target URL reachability check (cheap — 1 HTTP round-trip)
	const urlResult = await validateTargetUrl(targetUrl, logger);
	if (!urlResult.ok) {
		return urlResult;
	}

	logger.info("All preflight checks passed");
	return ok(undefined);
}
