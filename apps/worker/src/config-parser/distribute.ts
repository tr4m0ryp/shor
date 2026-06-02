// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import type { Config, DistributedConfig } from "../types/config.js";
import { sanitizeAuthentication, sanitizeRule } from "./sanitize.js";

export const distributeConfig = (config: Config | null): DistributedConfig => {
	const avoid = config?.rules?.avoid || [];
	const focus = config?.rules?.focus || [];
	const authentication = config?.authentication || null;
	const description = config?.description?.trim() || "";

	return {
		avoid: avoid.map(sanitizeRule),
		focus: focus.map(sanitizeRule),
		authentication: authentication
			? sanitizeAuthentication(authentication)
			: null,
		description,
	};
};
