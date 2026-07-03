// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from 'vitest';
import { coerceJson, extractJsonCandidate, salvageArrayPrefix, scanBalanced } from './local.js';

describe('extractJsonCandidate', () => {
  it('strips a ```json code fence', () => {
    const c = extractJsonCandidate('```json\n{"a": 1}\n```');
    expect(c).toEqual({ text: '{"a": 1}', terminated: true });
  });

  it('strips surrounding prose', () => {
    const c = extractJsonCandidate('Here is the result: {"a":1}. Done.');
    expect(c?.text).toBe('{"a":1}');
    expect(c?.terminated).toBe(true);
  });

  it('marks an unterminated (truncated) object as not terminated', () => {
    const c = extractJsonCandidate('```json\n{"a": 1, "b":');
    expect(c?.terminated).toBe(false);
    expect(c?.text.startsWith('{"a": 1')).toBe(true);
  });

  it('returns null when there is no JSON container', () => {
    expect(extractJsonCandidate('no json here')).toBeNull();
  });

  it('is not fooled by brackets inside strings', () => {
    const c = extractJsonCandidate('{"s": "a } b ] c"}');
    expect(c).toEqual({ text: '{"s": "a } b ] c"}', terminated: true });
  });
});

describe('scanBalanced', () => {
  it('returns -1 for an unterminated container', () => {
    expect(scanBalanced('[1, 2, 3', 0)).toBe(-1);
  });
  it('returns the index past the close for a balanced container', () => {
    expect(scanBalanced('[1]tail', 0)).toBe(3);
  });
});

describe('coerceJson (jsonrepair, complete-but-malformed only)', () => {
  it('parses valid JSON directly', () => {
    expect(coerceJson('{"a":1}')).toEqual({ ok: true, value: { a: 1 } });
  });

  it('repairs a trailing comma', () => {
    expect(coerceJson('{"a":1,}')).toEqual({ ok: true, value: { a: 1 } });
  });

  it('repairs single quotes and unquoted keys', () => {
    expect(coerceJson("{a: 'x'}")).toEqual({ ok: true, value: { a: 'x' } });
  });
});

describe('salvageArrayPrefix (truncation-safe — never fabricates)', () => {
  it('drops an incomplete trailing element and keeps the complete prefix', () => {
    // Third element is cut off mid-object; only the first two survive.
    const out = salvageArrayPrefix('[{"a":1},{"b":2},{"c":');
    expect(out).toBe('[{"a":1},{"b":2}]');
    expect(JSON.parse(out as string)).toEqual([{ a: 1 }, { b: 2 }]);
  });

  it('returns null when not even one element is complete', () => {
    expect(salvageArrayPrefix('[{"a":')).toBeNull();
  });

  it('returns null for a non-array', () => {
    expect(salvageArrayPrefix('{"a":1')).toBeNull();
  });

  it('drops a truncated trailing primitive (could be cut mid-number)', () => {
    // `123` may have been `1234`; it runs to EOF with no delimiter -> dropped.
    expect(salvageArrayPrefix('[1, 2, 123')).toBe('[1,2]');
  });
});
