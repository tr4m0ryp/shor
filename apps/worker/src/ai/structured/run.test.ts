// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the executor barrel so no real SDK call happens. `vi.hoisted` makes the
// spy available to the hoisted `vi.mock` factory.
const runClaudePromptMock = vi.hoisted(() => vi.fn());
vi.mock('../claude-executor/index.js', () => ({
  runClaudePrompt: runClaudePromptMock,
}));

import type { JsonSchemaOutputFormat } from '@anthropic-ai/claude-agent-sdk';
import { parseOr, runStructured, type StructuredResult } from './run.js';

const SCHEMA: JsonSchemaOutputFormat = { type: 'json_schema', schema: { type: 'object' } };

describe('runStructured', () => {
  beforeEach(() => {
    runClaudePromptMock.mockReset();
  });

  it('returns ok with the typed structured output on success', async () => {
    const value = { id: 'f1', verdict: 'refute', reason: 'no reachable sink' };
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1, structuredOutput: value });

    const res = await runStructured<typeof value>({ prompt: 'P', sourceDir: '/repo', schema: SCHEMA });

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.value).toEqual(value);
    expect(res.raw.success).toBe(true);
  });

  it('wraps the schema into the runClaudePrompt outputFormat slot', async () => {
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1, structuredOutput: {} });

    await runStructured({ prompt: 'P', sourceDir: '/repo', schema: SCHEMA, agentName: 'screen' });

    const call = runClaudePromptMock.mock.calls[0];
    if (!call) throw new Error('runClaudePrompt was not called');
    expect(call[1]).toBe('/repo'); // sourceDir
    expect(call[3]).toBe('screen'); // description derived from agentName
    expect(call[8]).toBe(SCHEMA); // outputFormat positional slot
  });

  it('returns ok:false when the agent run failed', async () => {
    runClaudePromptMock.mockResolvedValue({ success: false, duration: 1, error: 'boom' });

    const res = await runStructured({ prompt: 'P', sourceDir: '/repo', schema: SCHEMA });

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.error).toBe('boom');
    expect(res.raw.success).toBe(false);
  });

  it('returns ok:false when structuredOutput is missing or not an object', async () => {
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1 });

    const res = await runStructured({ prompt: 'P', sourceDir: '/repo', schema: SCHEMA });

    expect(res.ok).toBe(false);
  });

  it('never throws when the runner rejects', async () => {
    runClaudePromptMock.mockRejectedValue(new Error('kaboom'));

    const res = await runStructured({ prompt: 'P', sourceDir: '/repo', schema: SCHEMA });

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.error).toBe('kaboom');
    expect(res.raw.success).toBe(false);
  });
});

describe('parseOr', () => {
  it('returns the value on ok', () => {
    const res: StructuredResult<number> = { ok: true, value: 42, raw: { success: true, duration: 0 } };
    expect(parseOr(res, 0)).toBe(42);
  });

  it('returns the fallback on failure (fail-open default)', () => {
    const res: StructuredResult<number> = { ok: false, error: 'x', raw: { success: false, duration: 0 } };
    expect(parseOr(res, 7)).toBe(7);
  });
});
