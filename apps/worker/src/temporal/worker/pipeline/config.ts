// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { parseConfig } from "../../../config-parser.js";
import type { PipelineConfig } from "../../../types/config.js";

export interface LoadedConfig {
	pipelineConfig: PipelineConfig;
}

/** Loads the pipeline section from a YAML config; returns empty defaults on failure. */
export async function loadPipelineConfig(
	configPath: string | undefined,
): Promise<LoadedConfig> {
	if (!configPath) return { pipelineConfig: {} };
	try {
		const config = await parseConfig(configPath);

		const pipelineConfig: PipelineConfig = {};
		const raw = config.pipeline;
		if (raw) {
			if (raw.retry_preset !== undefined) {
				pipelineConfig.retry_preset = raw.retry_preset;
			}
			if (raw.max_concurrent_pipelines !== undefined) {
				pipelineConfig.max_concurrent_pipelines = Number(
					raw.max_concurrent_pipelines,
				);
			}
		}

		return { pipelineConfig };
	} catch {
		return { pipelineConfig: {} };
	}
}
