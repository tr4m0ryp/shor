// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Temporal workflow entry point.
 *
 * The implementation lives in `./workflows/`. This module re-exports the
 * workflow functions so Temporal's worker bundler (`workflowsPath`) keeps
 * discovering them at the original path without configuration changes.
 */

export * from "./workflows/index.js";
