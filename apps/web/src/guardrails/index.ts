// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Guardrails / safety layer — public surface (LAUNCH-SPEC §5.6, §3.3; Phase 6,
 * ADR-008 / ADR-022 / ADR-049; OWASP-APTS aligned).
 *
 * Code-enforced boundary controls, not prompt-only:
 *   - `roe`        — per-target Rules of Engagement; scope check before each run
 *                    AND before each network action (default-deny allowlist).
 *   - `rate-limit` — per-host token-bucket (no-DoS).
 *   - `egress`     — default-deny outbound allowlist derived from RoE + GitHub
 *                    App hosts; metadata endpoint + internal ranges hard-blocked.
 *   - `redaction`  — secret/token/PII redactor for logs + evidence.
 *   - `kill-switch`— wraps Temporal cancellation + per-run teardown/blast-radius.
 *   - `audit`      — tamper-proof tee to Cloud Audit Logs + pgMemento (redacted).
 *
 * Re-exported here (NOT from `src/index.ts`, which is wired at integration).
 */

export {
  type Roe,
  type RoeHostRule,
  type RoeScheme,
  ROE_SCHEMES,
  type RoeValidationError,
  RoeViolationError,
  type ValidatedRoe,
  assertInScope,
  isInScope,
  validateRoe,
} from './roe.js';

export {
  HostRateLimiter,
  type RateLimitConfig,
  RateLimitTimeoutError,
  getRateLimiter,
  resetRateLimiter,
} from './rate-limit.js';

export {
  type EgressAllowlist,
  EgressDeniedError,
  GITHUB_APP_HOSTS,
  deriveEgressAllowlist,
  deriveEgressAllowlistFromConfig,
  guardOutbound,
  isEgressAllowed,
} from './egress.js';

export {
  METADATA_HOSTNAMES,
  METADATA_IP,
  isBlockedHost,
  isBlockedIpv4,
  isBlockedIpv6,
} from './net.js';

export { containsSecret, redact, redactValue } from './redaction.js';

export {
  AuditTee,
  type AuditEvent,
  type AuditEventInput,
  type AuditEventType,
  type AuditOutcome,
  type AuditSink,
  consoleAuditSink,
  getAuditTee,
  resetAuditTee,
  toRedactedEvent,
} from './audit.js';

export {
  type BlastRadiusBreach,
  type BlastRadiusCaps,
  BlastRadiusMonitor,
  DEFAULT_BLAST_RADIUS_CAPS,
  type KillReason,
  type TeardownHook,
  killScan,
} from './kill-switch.js';
