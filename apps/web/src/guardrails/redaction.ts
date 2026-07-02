// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Secret / token / PII redaction for logs and evidence (LAUNCH-SPEC §5.6;
 * ADR-049; OWASP-APTS secret redaction).
 *
 * Applied at the boundary before anything is written to Cloud Audit Logs, the
 * pgMemento delta log, or persisted finding evidence. Provider keys are already
 * file-mounted (never env material), but agent output, tool stdout, and HTTP
 * captures can still echo a token — this is the last line of defense.
 *
 * Pure + dependency-free, no I/O. Conservative by design: a false positive
 * (over-redaction) is acceptable; leaking a credential is not.
 */

const REDACTED = '[REDACTED]';

interface Rule {
  readonly name: string;
  readonly pattern: RegExp;
  /** Replacement; `$1` etc. supported to keep a non-secret prefix label. */
  readonly replacement: string;
}

/**
 * Ordered redaction rules. Each `pattern` MUST be constructed fresh per call
 * (global regexes carry `lastIndex` state), so we store source + flags and
 * compile on use.
 */
const RULES: readonly Rule[] = [
  // Authorization: Bearer <token>  /  bearer <token>
  { name: 'bearer', pattern: /\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}/gi, replacement: `$1 ${REDACTED}` },
  // JWT: three base64url segments separated by dots.
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}/g, replacement: REDACTED },
  // GitHub tokens (PAT / installation / OAuth / refresh / server).
  { name: 'github-token', pattern: /\bgh[posru]_[A-Za-z0-9]{16,}/g, replacement: REDACTED },
  { name: 'github-pat-v2', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/g, replacement: REDACTED },
  // Anthropic / OpenAI style keys.
  { name: 'anthropic-key', pattern: /\bsk-ant-[A-Za-z0-9_-]{16,}/g, replacement: REDACTED },
  { name: 'openai-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g, replacement: REDACTED },
  // Google API key.
  { name: 'google-api-key', pattern: /\bAIza[A-Za-z0-9_-]{20,}/g, replacement: REDACTED },
  // AWS access key id + secret access key.
  { name: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replacement: REDACTED },
  { name: 'aws-secret', pattern: /\baws_secret_access_key\s*[=:]\s*\S+/gi, replacement: `aws_secret_access_key=${REDACTED}` },
  // Slack tokens.
  { name: 'slack-token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, replacement: REDACTED },
  // Private key PEM blocks.
  {
    name: 'pem',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
    replacement: REDACTED,
  },
  // Generic "secret/token/password/api_key = value" assignments.
  {
    name: 'generic-assignment',
    pattern: /\b(api[_-]?key|secret|token|password|passwd|pwd|authorization)\b\s*[=:]\s*["']?[A-Za-z0-9._~+/=-]{6,}["']?/gi,
    replacement: `$1=${REDACTED}`,
  },
  // Basic-auth credentials embedded in a URL (user:pass@host).
  { name: 'url-userinfo', pattern: /(\bhttps?:\/\/)[^/\s:@]+:[^/\s@]+@/gi, replacement: `$1${REDACTED}@` },
  // Email addresses (PII).
  { name: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: REDACTED },
];

/** Redact secrets/tokens/PII from a string. Idempotent and side-effect free. */
export function redact(text: string): string {
  if (!text) return text;
  let out = text;
  for (const rule of RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags);
    out = out.replace(re, rule.replacement);
  }
  return out;
}

/**
 * Deep-redact a structured value (object/array/string). Keys are preserved;
 * string values are run through `redact`. Cycles are tolerated. Use this for
 * audit-event payloads before they leave the process.
 */
export function redactValue<T>(value: T): T {
  return redactInner(value, new WeakSet()) as T;
}

function redactInner(value: unknown, seen: WeakSet<object>): unknown {
  if (typeof value === 'string') return redact(value);
  if (value === null || typeof value !== 'object') return value;
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);

  if (Array.isArray(value)) return value.map((v) => redactInner(v, seen));

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    // Redact the value entirely when the KEY itself names a secret.
    out[k] = /(secret|token|password|api[_-]?key|authorization|private[_-]?key)/i.test(k)
      ? typeof v === 'string'
        ? REDACTED
        : redactInner(v, seen)
      : redactInner(v, seen);
  }
  return out;
}

/** Predicate: does `text` contain anything the redactor would mask? */
export function containsSecret(text: string): boolean {
  return redact(text) !== text;
}
