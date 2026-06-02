// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { SessionMutex } from "../../utils/concurrency.js";

/**
 * Global mutex shared by every AuditSession instance.
 *
 * IMPORTANT: AuditSession is intentionally excluded from the DI container; each
 * agent execution constructs its own instance for instance-state isolation
 * (currentAgentName, currentLogger). Serialization of writes to session.json
 * across parallel phases is provided by this process-wide mutex, keyed by
 * sessionId.
 */
export const sessionMutex = new SessionMutex();
