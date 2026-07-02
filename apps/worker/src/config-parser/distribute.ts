// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
