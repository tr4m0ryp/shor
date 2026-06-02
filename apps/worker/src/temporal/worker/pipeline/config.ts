// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
