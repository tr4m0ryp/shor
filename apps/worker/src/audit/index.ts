// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Unified Audit & Metrics System
 *
 * Public API for the audit system. Provides crash-safe, append-only logging
 * and comprehensive metrics tracking for Storron penetration testing sessions.
 *
 * IMPORTANT: Session objects must have an 'id' field (NOT 'sessionId')
 * Example: { id: "uuid", webUrl: "...", repoPath: "..." }
 *
 * @module audit
 */

export { AuditSession } from "./audit-session.js";
