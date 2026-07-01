/**
 * Tamper-proof audit tee (LAUNCH-SPEC §5.6; ADR-049).
 *
 * Structured guardrail/security events are emitted to TWO sinks so the trail is
 * tamper-evident across layers: Cloud Audit Logs (immutable, GCP-side) and the
 * pgMemento delta log (DB-side row history). This module is the seam: it defines
 * the event shape, applies redaction, and tees to both sinks. The concrete sink
 * implementations (Cloud Logging client, pg insert) are injected — keeping this
 * module pure and I/O-free at import so it compiles with no live credentials.
 */

import { redact, redactValue } from './redaction.js';

/** Audit event categories the guardrail layer emits. */
export type AuditEventType =
  | 'roe.validated'
  | 'roe.violation'
  | 'egress.allowed'
  | 'egress.denied'
  | 'rate_limit.throttled'
  | 'kill_switch.triggered'
  | 'scan.teardown'
  | 'blast_radius.exceeded'
  // A scan started via the MCP connector after a launch token was consumed. Its
  // detail links engagementId -> roeHash -> launch-grant id -> scanId -> hosts, so
  // "what authorized this scan?" is answerable in one query (never the token value).
  | 'launch.authorized';

export type AuditOutcome = 'allow' | 'deny' | 'info';

/** A structured, redacted audit event. */
export interface AuditEvent {
  readonly type: AuditEventType;
  readonly outcome: AuditOutcome;
  /** Tenant the event belongs to (row-level audit scoping). */
  readonly tenantId: string;
  /** Scan/run correlation id, when applicable. */
  readonly scanId?: string;
  /** Actor: a user id, a service-identity email, or `system`. */
  readonly actor?: string;
  /** Human-readable summary (already redacted before emit). */
  readonly message: string;
  /** Structured detail (deep-redacted before emit). */
  readonly detail?: Record<string, unknown>;
  /** ISO-8601 emit time. */
  readonly at: string;
}

/** Fields a caller supplies; `at` is stamped and redaction is applied for them. */
export interface AuditEventInput {
  readonly type: AuditEventType;
  readonly outcome: AuditOutcome;
  readonly tenantId: string;
  readonly scanId?: string;
  readonly actor?: string;
  readonly message: string;
  readonly detail?: Record<string, unknown>;
}

/** A single downstream audit sink (Cloud Audit Logs OR the pgMemento log). */
export interface AuditSink {
  readonly name: string;
  emit(event: AuditEvent): Promise<void> | void;
}

/**
 * The audit tee: applies redaction once, then fans the event out to every sink.
 * A sink failure is isolated (logged to stderr) so one broken sink never drops
 * the event on the others — the audit trail must be best-effort durable.
 */
export class AuditTee {
  constructor(private readonly sinks: readonly AuditSink[]) {}

  async emit(input: AuditEventInput): Promise<void> {
    const event = toRedactedEvent(input);
    await Promise.all(
      this.sinks.map(async (sink) => {
        try {
          await sink.emit(event);
        } catch (err) {
          // Never throw from the audit path; surface the sink failure only.
          // eslint-disable-next-line no-console
          console.error(`[audit] sink "${sink.name}" failed:`, err);
        }
      }),
    );
  }
}

/** Stamp `at` and run message + detail through the redactor. */
export function toRedactedEvent(input: AuditEventInput): AuditEvent {
  const base: {
    type: AuditEventType;
    outcome: AuditOutcome;
    tenantId: string;
    message: string;
    at: string;
    scanId?: string;
    actor?: string;
    detail?: Record<string, unknown>;
  } = {
    type: input.type,
    outcome: input.outcome,
    tenantId: input.tenantId,
    message: redact(input.message),
    at: new Date().toISOString(),
  };
  if (input.scanId !== undefined) base.scanId = input.scanId;
  if (input.actor !== undefined) base.actor = redact(input.actor);
  if (input.detail !== undefined) base.detail = redactValue(input.detail);
  return base;
}

/**
 * Default `AuditSink` that writes structured JSON to stderr — the shape Cloud
 * Run / Cloud Logging ingests as a structured log entry. Used as a safe
 * fallback and in local/dev where the Cloud Audit + pgMemento sinks are not
 * wired (those are injected at integration).
 */
export const consoleAuditSink: AuditSink = {
  name: 'console',
  emit(event: AuditEvent): void {
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ severity: severityFor(event.outcome), ...event }));
  },
};

function severityFor(outcome: AuditOutcome): string {
  switch (outcome) {
    case 'deny':
      return 'WARNING';
    case 'allow':
      return 'INFO';
    default:
      return 'NOTICE';
  }
}

let shared: AuditTee | undefined;

/** Process-wide audit tee; defaults to the console sink until sinks are wired. */
export function getAuditTee(sinks?: readonly AuditSink[]): AuditTee {
  if (sinks) {
    shared = new AuditTee(sinks);
    return shared;
  }
  if (!shared) shared = new AuditTee([consoleAuditSink]);
  return shared;
}

/** Test hook: drop the shared tee. */
export function resetAuditTee(): void {
  shared = undefined;
}
