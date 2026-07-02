// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from 'vitest';
import { demoteDevCredentials } from './dev-credential-guard.js';
import type { FindingRecord } from './types.js';

const logger = { info() {}, warn() {}, error() {}, debug() {} } as unknown as Parameters<
  typeof demoteDevCredentials
>[2];

function rec(over: Partial<FindingRecord>): FindingRecord {
  return {
    id: 'X',
    title: 'Hardcoded signing key',
    category: 'auth',
    cwe: 'CWE-798',
    severity: 'critical',
    confidence: 'firm',
    evidence: '',
    safe_poc: '',
    missing_defense: '',
    remediation: '',
    ...over,
  } as unknown as FindingRecord;
}

const run = (r: FindingRecord): FindingRecord => {
  const [out] = demoteDevCredentials([r], undefined, logger);
  if (!out) throw new Error('no result');
  return out;
};

describe('demoteDevCredentials', () => {
  it('demotes a key marked `// For local testing` to low', () => {
    const out = run(rec({ evidence: 'CanvasLti:Key = "abc123def456abc1" // For local testing' }));
    expect(out.severity).toBe('low');
    expect(out.dev_credential_scaffolding).toBe(true);
  });

  it('demotes a doubled hand-typed fake value (its own two halves)', () => {
    // value = "blawlaekltjwelkrj32" + same again → never a real key
    const out = run(rec({ evidence: 'key: "blawlaekltjwelkrj32blawlaekltjwelkrj32"' }));
    expect(out.severity).toBe('low');
  });

  it('demotes a known placeholder value', () => {
    const out = run(rec({ evidence: 'InvitationApiToken = "replace-me"' }));
    expect(out.severity).toBe('low');
  });

  it('LEAVES a high-entropy, unmarked secret alone (could be a real leak)', () => {
    const out = run(rec({ evidence: 'SigningKey = "9c01d90e4163ce3abd462556b29d588e44477b0ac"' }));
    expect(out.severity).toBe('critical');
    expect(out.dev_credential_scaffolding).toBeUndefined();
  });

  it('ignores non-secret findings entirely', () => {
    const out = run(rec({ cwe: 'CWE-918', title: 'SSRF', evidence: 'outbound request, for local testing env' }));
    expect(out.severity).toBe('critical');
  });
});
