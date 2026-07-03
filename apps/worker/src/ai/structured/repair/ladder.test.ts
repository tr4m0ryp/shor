// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { attemptLocalRepair, buildReaskInstruction, isTruncationStop } from './ladder.js';

const objSchema = z.object({ id: z.string(), n: z.number() });
const arrSchema = z.array(z.object({ id: z.string() }));

describe('isTruncationStop', () => {
  it('recognises length cut-offs', () => {
    expect(isTruncationStop('max_tokens')).toBe(true);
    expect(isTruncationStop('length')).toBe(true);
    expect(isTruncationStop('MAX_OUTPUT_TOKENS')).toBe(true);
  });
  it('is false for a clean stop', () => {
    expect(isTruncationStop('end_turn')).toBe(false);
    expect(isTruncationStop(null)).toBe(false);
    expect(isTruncationStop(undefined)).toBe(false);
  });
});

describe('attemptLocalRepair — well-formed / SDK path', () => {
  it('validates a present SDK object without repairing it', () => {
    const out = attemptLocalRepair({ rawText: null, structured: { id: 'x', n: 1 }, validator: objSchema });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') throw new Error('expected ok');
    expect(out.meta).toEqual({ repaired: false, method: 'sdk', truncated: false, schemaValidated: true });
    expect(out.value).toEqual({ id: 'x', n: 1 });
  });
});

describe('attemptLocalRepair — complete-but-malformed (tier 3, jsonrepair)', () => {
  it('repairs fenced + trailing-comma JSON, then re-validates and flags it', () => {
    const out = attemptLocalRepair({
      rawText: '```json\n{"id":"a","n":2,}\n```',
      validator: objSchema,
    });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') throw new Error('expected ok');
    expect(out.value).toEqual({ id: 'a', n: 2 });
    expect(out.meta.repaired).toBe(true);
    expect(out.meta.method).toBe('jsonrepair');
    expect(out.meta.truncated).toBe(false);
    expect(out.meta.schemaValidated).toBe(true);
  });

  it('parses already-valid raw text the SDK failed to capture (tier 1b)', () => {
    const out = attemptLocalRepair({ rawText: '{"id":"a","n":2}', validator: objSchema });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') throw new Error('expected ok');
    expect(out.meta.method).toBe('parsed-raw');
  });

  it('reports invalid when repaired JSON fails the full schema', () => {
    const out = attemptLocalRepair({ rawText: '{"id":123,}', validator: objSchema });
    expect(out.status).toBe('invalid');
  });

  it('object-shape only when no validator is supplied', () => {
    const out = attemptLocalRepair({ rawText: '{"anything":true,}' });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') throw new Error('expected ok');
    expect(out.meta.schemaValidated).toBe(false);
  });
});

describe('attemptLocalRepair — TRUNCATION (must NOT fabricate closers)', () => {
  it('routes a truncated single object to re-run, never a silent close', () => {
    const out = attemptLocalRepair({
      rawText: '{"id":"a","n":2, "extra": "lots of text that got cut o',
      stopReason: 'max_tokens',
      validator: objSchema,
    });
    // Critically: not "ok" — a truncated object is never invented into validity.
    expect(out.status).toBe('truncated');
  });

  it('salvages the complete prefix of a truncated findings array (drops the cut element)', () => {
    // Three findings started; the third was cut off. Only the first two are real.
    const out = attemptLocalRepair({
      rawText: '[{"id":"f1"},{"id":"f2"},{"id":"f3',
      stopReason: 'max_tokens',
      validator: arrSchema,
    });
    expect(out.status).toBe('ok');
    if (out.status !== 'ok') throw new Error('expected ok');
    expect(out.value).toEqual([{ id: 'f1' }, { id: 'f2' }]); // f3 dropped, NOT fabricated
    expect(out.meta.truncated).toBe(true);
    expect(out.meta.method).toBe('salvaged-array-prefix');
  });

  it('detects truncation structurally even without a stop_reason', () => {
    const out = attemptLocalRepair({ rawText: '{"id":"a","n":', validator: objSchema });
    expect(out.status).toBe('truncated');
  });
});

describe('buildReaskInstruction', () => {
  it('asks for a shorter complete answer on truncation', () => {
    const msg = buildReaskInstruction({ status: 'truncated', reason: 'x', diagnostic: '' });
    expect(msg.toLowerCase()).toContain('cut off');
    expect(msg.toLowerCase()).toContain('complete');
  });
  it('feeds the schema error back on an invalid body', () => {
    const msg = buildReaskInstruction({ status: 'invalid', reason: 'bad field foo', diagnostic: '' });
    expect(msg).toContain('bad field foo');
  });
});
