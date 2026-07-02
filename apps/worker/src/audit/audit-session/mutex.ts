// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

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
