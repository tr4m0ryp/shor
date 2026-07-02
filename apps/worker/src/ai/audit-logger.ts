// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

// Null Object pattern for audit logging - callers never check for null

import type { AuditSession } from "../audit/index.js";
import { formatTimestamp } from "../utils/formatting.js";

export interface AuditLogger {
	logLlmResponse(turn: number, content: string): Promise<void>;
	logToolStart(toolName: string, parameters: unknown): Promise<void>;
	logToolEnd(result: unknown): Promise<void>;
	logError(error: Error, duration: number, turns: number): Promise<void>;
}

class RealAuditLogger implements AuditLogger {
	private auditSession: AuditSession;

	constructor(auditSession: AuditSession) {
		this.auditSession = auditSession;
	}

	async logLlmResponse(turn: number, content: string): Promise<void> {
		await this.auditSession.logEvent("llm_response", {
			turn,
			content,
			timestamp: formatTimestamp(),
		});
	}

	async logToolStart(toolName: string, parameters: unknown): Promise<void> {
		await this.auditSession.logEvent("tool_start", {
			toolName,
			parameters,
			timestamp: formatTimestamp(),
		});
	}

	async logToolEnd(result: unknown): Promise<void> {
		await this.auditSession.logEvent("tool_end", {
			result,
			timestamp: formatTimestamp(),
		});
	}

	async logError(error: Error, duration: number, turns: number): Promise<void> {
		await this.auditSession.logEvent("error", {
			message: error.message,
			errorType: error.constructor.name,
			stack: error.stack,
			duration,
			turns,
			timestamp: formatTimestamp(),
		});
	}
}

/** Null Object implementation - all methods are safe no-ops */
class NullAuditLogger implements AuditLogger {
	async logLlmResponse(_turn: number, _content: string): Promise<void> {}

	async logToolStart(_toolName: string, _parameters: unknown): Promise<void> {}

	async logToolEnd(_result: unknown): Promise<void> {}

	async logError(
		_error: Error,
		_duration: number,
		_turns: number,
	): Promise<void> {}
}

// Returns no-op when auditSession is null
export function createAuditLogger(
	auditSession: AuditSession | null,
): AuditLogger {
	if (auditSession) {
		return new RealAuditLogger(auditSession);
	}

	return new NullAuditLogger();
}
