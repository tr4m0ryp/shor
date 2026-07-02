// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { fs, path } from "zx";
import type { ActivityLogger } from "../../types/activity-logger.js";

/**
 * Env var naming the file-mounted provider-key path (ADR-050). The control
 * plane mounts the single selected provider key as a volume file (never an env
 * value) and points this at it; the engine reads the file at use time. Mirrors
 * `apps/web/src/secrets/injection.ts` (`PROVIDER_KEY_FILE_ENV`).
 */
export const PROVIDER_KEY_FILE_ENV = "SHOR_PROVIDER_KEY_FILE";

/**
 * Read the provider API key from the file-mounted path named by
 * `SHOR_PROVIDER_KEY_FILE`, if set and present. Returns the trimmed material,
 * or undefined when the env var is unset / the file is missing or empty.
 *
 * Read at use time (not import time) so a rotated mount is picked up and so a
 * plaintext key is never held in long-lived process state.
 */
async function readProviderKeyFile(): Promise<string | undefined> {
	const keyFile = process.env[PROVIDER_KEY_FILE_ENV];
	if (!keyFile) return undefined;
	try {
		if (!(await fs.pathExists(keyFile))) return undefined;
		const material = (await fs.readFile(keyFile, "utf8")).trim();
		return material || undefined;
	} catch {
		// A mount race or transient read error should not crash env assembly;
		// fall through to other key sources (passthrough env, providerConfig).
		return undefined;
	}
}

export interface SdkEnvParams {
	sourceDir: string;
	agentName: string | null;
	apiKey?: string | undefined;
	deliverablesSubdir?: string | undefined;
	providerConfig?: import("../../types/config.js").ProviderConfig | undefined;
	extraEnv?: Record<string, string> | undefined;
	logger: ActivityLogger;
}

/**
 * Build the env map passed to the Claude Agent SDK subprocess. Layers, in order:
 * base defaults, provider-config-derived overrides, passthrough process.env variables,
 * and caller-supplied extraEnv overrides.
 */
export async function buildSdkEnv(
	params: SdkEnvParams,
): Promise<Record<string, string>> {
	const {
		sourceDir,
		apiKey,
		deliverablesSubdir,
		providerConfig,
		extraEnv,
	} = params;

	// 1. Base env: SDK output ceiling and Playwright output dir; optionally seed ANTHROPIC_API_KEY.
	const sdkEnv: Record<string, string> = {
		CLAUDE_CODE_MAX_OUTPUT_TOKENS:
			process.env.CLAUDE_CODE_MAX_OUTPUT_TOKENS || "64000",
		PLAYWRIGHT_MCP_OUTPUT_DIR: deliverablesSubdir
			? path.join(
					sourceDir,
					path.dirname(deliverablesSubdir),
					".playwright-cli",
				)
			: path.join(sourceDir, ".storron", ".playwright-cli"),
		// apiKey from ContainerConfig takes precedence over process.env
		...(apiKey && { ANTHROPIC_API_KEY: apiKey }),
		// Deliverables subdir for save-deliverable CLI tool
		...(deliverablesSubdir && {
			STORRON_DELIVERABLES_SUBDIR: deliverablesSubdir,
		}),
	};

	// 1b. File-mounted provider key (ADR-050): when no explicit apiKey was passed,
	//     source the selected provider key from the mounted secret file at use
	//     time and seed ANTHROPIC_API_KEY. providerConfig (below) still wins.
	if (!apiKey) {
		const mountedKey = await readProviderKeyFile();
		if (mountedKey) {
			sdkEnv.ANTHROPIC_API_KEY = mountedKey;
		}
	}

	// 2. DeepSeek auto-detection: if DEEPSEEK_API_KEY is set and no other provider
	//    is configured, route through DeepSeek's Anthropic-compatible endpoint.
	const deepseekApiKey = process.env.DEEPSEEK_API_KEY;
	if (deepseekApiKey && !providerConfig && !sdkEnv.ANTHROPIC_BASE_URL) {
		sdkEnv.ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic";
		sdkEnv.ANTHROPIC_AUTH_TOKEN = deepseekApiKey;
	}

	// 3. Apply structured provider config directly to sdkEnv (no process.env mutation)
	if (providerConfig) {
		switch (providerConfig.providerType) {
			case "deepseek":
				sdkEnv.ANTHROPIC_BASE_URL = "https://api.deepseek.com/anthropic";
				sdkEnv.ANTHROPIC_AUTH_TOKEN =
					providerConfig.apiKey || deepseekApiKey || "";
				break;
			case "bedrock":
				sdkEnv.CLAUDE_CODE_USE_BEDROCK = "1";
				if (providerConfig.awsRegion)
					sdkEnv.AWS_REGION = providerConfig.awsRegion;
				if (providerConfig.awsAccessKeyId)
					sdkEnv.AWS_ACCESS_KEY_ID = providerConfig.awsAccessKeyId;
				if (providerConfig.awsSecretAccessKey)
					sdkEnv.AWS_SECRET_ACCESS_KEY = providerConfig.awsSecretAccessKey;
				break;
			case "vertex":
				sdkEnv.CLAUDE_CODE_USE_VERTEX = "1";
				if (providerConfig.gcpRegion)
					sdkEnv.CLOUD_ML_REGION = providerConfig.gcpRegion;
				if (providerConfig.gcpProjectId)
					sdkEnv.ANTHROPIC_VERTEX_PROJECT_ID = providerConfig.gcpProjectId;
				if (providerConfig.gcpCredentialsPath)
					sdkEnv.GOOGLE_APPLICATION_CREDENTIALS =
						providerConfig.gcpCredentialsPath;
				break;
			case "litellm_router":
				if (providerConfig.baseUrl)
					sdkEnv.ANTHROPIC_BASE_URL = providerConfig.baseUrl;
				if (providerConfig.authToken)
					sdkEnv.ANTHROPIC_AUTH_TOKEN = providerConfig.authToken;
				if (providerConfig.routerDefault)
					sdkEnv.ROUTER_DEFAULT = providerConfig.routerDefault;
				break;
			default:
				// 'anthropic_api' or unset — apiKey already handled above
				if (providerConfig.apiKey && !apiKey)
					sdkEnv.ANTHROPIC_API_KEY = providerConfig.apiKey;
				break;
		}
	}

	// 4. Passthrough env vars not already set by providerConfig or apiKey
	const passthroughVars = [
		...(!sdkEnv.ANTHROPIC_API_KEY ? ["ANTHROPIC_API_KEY"] : []),
		"CLAUDE_CODE_OAUTH_TOKEN",
		...(!sdkEnv.ANTHROPIC_BASE_URL ? ["ANTHROPIC_BASE_URL"] : []),
		...(!sdkEnv.ANTHROPIC_AUTH_TOKEN ? ["ANTHROPIC_AUTH_TOKEN"] : []),
		...(!sdkEnv.CLAUDE_CODE_USE_BEDROCK ? ["CLAUDE_CODE_USE_BEDROCK"] : []),
		...(!sdkEnv.AWS_REGION ? ["AWS_REGION"] : []),
		"AWS_BEARER_TOKEN_BEDROCK",
		...(!sdkEnv.CLAUDE_CODE_USE_VERTEX ? ["CLAUDE_CODE_USE_VERTEX"] : []),
		...(!sdkEnv.CLOUD_ML_REGION ? ["CLOUD_ML_REGION"] : []),
		...(!sdkEnv.ANTHROPIC_VERTEX_PROJECT_ID
			? ["ANTHROPIC_VERTEX_PROJECT_ID"]
			: []),
		...(!sdkEnv.GOOGLE_APPLICATION_CREDENTIALS
			? ["GOOGLE_APPLICATION_CREDENTIALS"]
			: []),
		"HOME",
		"PATH",
		"PLAYWRIGHT_MCP_EXECUTABLE_PATH",
	];
	for (const name of passthroughVars) {
		const val = process.env[name];
		if (val) {
			sdkEnv[name] = val;
		}
	}

	// 5. Per-agent overrides win over passthrough.
	if (extraEnv) {
		Object.assign(sdkEnv, extraEnv);
	}

	return sdkEnv;
}
