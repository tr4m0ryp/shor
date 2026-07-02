// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Public surface of the container module.
// `DEFAULT_CONFIG` is treated as a module-internal default and is intentionally
// not re-exported; callers pass an explicit `ContainerConfig` or rely on
// `getOrCreateContainer`'s default parameter.

export { Container } from "./container-class.js";
export {
	getContainer,
	getOrCreateContainer,
	removeContainer,
} from "./registry.js";
export type { ContainerDependencies } from "./types.js";
