// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

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
