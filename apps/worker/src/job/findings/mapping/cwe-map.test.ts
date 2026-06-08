// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Per-finding CWE mapper regression tests (T4).
 *
 * Locks in: explicit CWE wins; mechanism tokens map to the right CWE (killing the
 * CWE-287/CWE-862 monoculture); alg-confusion (CWE-347) is only assigned when the
 * mechanism is asymmetric→HMAC (or explicitly "algorithm confusion"); and a true
 * fall-through to the category default sets `inferred=true`.
 */

import { describe, expect, it } from 'vitest';
import type { FindingCategory } from '../types.js';
import { resolveCwe } from './cwe-map.js';

function raw(over: Record<string, unknown>): Record<string, unknown> {
  return over;
}

describe('resolveCwe — explicit CWE wins', () => {
  it('uses an explicit `cwe` and never marks it inferred', () => {
    const r = resolveCwe(raw({ cwe: 'CWE-1234', vulnerability_type: 'sqli' }), 'injection', 'CWE-89');
    expect(r).toEqual({ cwe: 'CWE-1234', inferred: false });
  });

  it('accepts the `cwe_id` alias too', () => {
    const r = resolveCwe(raw({ cwe_id: 'CWE-77' }), 'injection', 'CWE-89');
    expect(r.cwe).toBe('CWE-77');
    expect(r.inferred).toBe(false);
  });
});

describe('resolveCwe — mechanism mapping', () => {
  const cases: Array<[string, Record<string, unknown>, FindingCategory, string, string]> = [
    ['hardcoded key → CWE-798', { vulnerability_type: 'Hardcoded API key in source' }, 'auth', 'CWE-287', 'CWE-798'],
    ['open redirect → CWE-601', { vulnerability_type: 'Open Redirect' }, 'misconfig-web', 'CWE-16', 'CWE-601'],
    [
      'unvalidated redirect prose → CWE-601',
      { vulnerability_type: 'redirect', notes: 'arbitrary external redirect via next param' },
      'misconfig-web',
      'CWE-16',
      'CWE-601',
    ],
    ['SSRF → CWE-918', { vulnerability_type: 'Server-Side Request Forgery' }, 'ssrf', 'CWE-918', 'CWE-918'],
    [
      'log leak → CWE-532',
      { vulnerability_type: 'Sensitive data logging', notes: 'secret token written to logs' },
      'misconfig-web',
      'CWE-16',
      'CWE-532',
    ],
    ['path traversal → CWE-22', { vulnerability_type: 'Path Traversal' }, 'injection', 'CWE-89', 'CWE-22'],
    [
      'command injection → CWE-78',
      { vulnerability_type: 'OS command injection (RCE)' },
      'injection',
      'CWE-89',
      'CWE-78',
    ],
    ['csrf → CWE-352', { vulnerability_type: 'CSRF' }, 'misconfig-web', 'CWE-16', 'CWE-352'],
    ['deserialization → CWE-502', { vulnerability_type: 'Insecure deserialization' }, 'logic', 'CWE-840', 'CWE-502'],
    ['idor → CWE-639', { vulnerability_type: 'Horizontal IDOR' }, 'authz', 'CWE-862', 'CWE-639'],
    ['privesc → CWE-269', { vulnerability_type: 'Vertical privilege escalation' }, 'authz', 'CWE-862', 'CWE-269'],
  ];
  for (const [name, over, category, def, expected] of cases) {
    it(name, () => {
      const r = resolveCwe(raw(over), category, def);
      expect(r.cwe).toBe(expected);
      expect(r.inferred).toBe(false);
    });
  }
});

describe('resolveCwe — JWT algorithm confusion guard (CWE-347 only when asymmetric)', () => {
  it("maps explicit 'algorithm confusion' on a JWT to CWE-347", () => {
    const r = resolveCwe(
      raw({ vulnerability_type: 'JWT algorithm confusion', notes: 'RS256 verified with HS256' }),
      'auth',
      'CWE-287',
    );
    expect(r.cwe).toBe('CWE-347');
    expect(r.inferred).toBe(false);
  });

  it('maps asymmetric→HMAC key confusion to CWE-347', () => {
    const r = resolveCwe(
      raw({ vulnerability_type: 'JWT', notes: 'public RS256 key used as HS256 HMAC secret' }),
      'auth',
      'CWE-287',
    );
    expect(r.cwe).toBe('CWE-347');
  });

  it('maps alg:none / missing signature verification to CWE-347', () => {
    const r = resolveCwe(
      raw({ vulnerability_type: 'JWT alg:none accepted', notes: 'signature not verified' }),
      'auth',
      'CWE-287',
    );
    expect(r.cwe).toBe('CWE-347');
  });

  it('does NOT assign CWE-347 to an unrelated symmetric-only auth finding', () => {
    // A plain weak-password auth weakness must fall through to the default.
    const r = resolveCwe(raw({ vulnerability_type: 'Weak password policy' }), 'auth', 'CWE-287');
    expect(r.cwe).toBe('CWE-287');
    expect(r.inferred).toBe(true);
  });
});

describe('resolveCwe — category-default fallback sets cwe_inferred', () => {
  it('falls through to the category default when nothing matches', () => {
    const r = resolveCwe(raw({ vulnerability_type: 'some bespoke business rule' }), 'logic', 'CWE-840');
    expect(r).toEqual({ cwe: 'CWE-840', inferred: true });
  });

  it('falls through (inferred) when there is no mechanism text at all', () => {
    const r = resolveCwe(raw({}), 'authz', 'CWE-862');
    expect(r).toEqual({ cwe: 'CWE-862', inferred: true });
  });
});
