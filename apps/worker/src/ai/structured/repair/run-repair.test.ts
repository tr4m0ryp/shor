// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the executor barrel so no real SDK call happens (mirrors run.test.ts).
const runClaudePromptMock = vi.hoisted(() => vi.fn());
vi.mock('../../claude-executor/index.js', () => ({
  runClaudePrompt: runClaudePromptMock,
}));

import type { JsonSchemaOutputFormat } from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';
import { runStructured } from '../run.js';

const SCHEMA: JsonSchemaOutputFormat = { type: 'json_schema', schema: { type: 'object' } };
const objValidator = z.object({ id: z.string() });
const CORE = { prompt: 'P', sourceDir: '/repo', schema: SCHEMA } as const;

describe('runStructured auto-repair', () => {
  beforeEach(() => {
    runClaudePromptMock.mockReset();
    delete process.env.SHOR_STRUCTURED_REPAIR;
  });
  afterEach(() => {
    delete process.env.SHOR_STRUCTURED_REPAIR;
  });

  it('flag OFF: malformed raw text still fails-open, no repair attempted', async () => {
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1, result: '```json\n{"id":"a",}\n```' });

    const res = await runStructured(CORE);

    expect(res.ok).toBe(false);
    expect(runClaudePromptMock).toHaveBeenCalledTimes(1);
  });

  it('flag OFF: well-formed structured output is unchanged', async () => {
    const value = { id: 'a' };
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1, structuredOutput: value });

    const res = await runStructured<typeof value>(CORE);
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.value).toEqual(value);
    expect(res.repair).toBeUndefined(); // stock path never carries a repair flag
  });

  it('flag ON: repairs malformed fenced JSON locally, no re-run, flags it', async () => {
    process.env.SHOR_STRUCTURED_REPAIR = '1';
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1, result: '```json\n{"id":"a",}\n```' });

    const res = await runStructured({ ...CORE, validator: objValidator });

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.value).toEqual({ id: 'a' });
    expect(res.repair?.method).toBe('jsonrepair');
    expect(res.repair?.repaired).toBe(true);
    expect(runClaudePromptMock).toHaveBeenCalledTimes(1); // local repair, no re-inference
  });

  it('flag ON: well-formed structured output stays on the fast path (no repair flag)', async () => {
    process.env.SHOR_STRUCTURED_REPAIR = '1';
    const value = { id: 'a' };
    runClaudePromptMock.mockResolvedValue({ success: true, duration: 1, structuredOutput: value });

    const res = await runStructured<typeof value>(CORE);
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.repair).toBeUndefined();
  });

  it('flag ON: a truncated object is routed to a re-run (NOT silently closed)', async () => {
    process.env.SHOR_STRUCTURED_REPAIR = '1';
    // Attempt 1: truncated body + max_tokens. Attempt 2 (reask): clean structured output.
    runClaudePromptMock
      .mockResolvedValueOnce({
        success: true,
        duration: 1,
        result: '{"id":"a", "x": "cut o',
        stop_reason: 'max_tokens',
      })
      .mockResolvedValueOnce({ success: true, duration: 1, structuredOutput: { id: 'a' } });

    const res = await runStructured({ ...CORE, validator: objValidator });

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error('expected ok');
    expect(res.value).toEqual({ id: 'a' });
    expect(runClaudePromptMock).toHaveBeenCalledTimes(2); // truncation triggered a re-run
    const secondPrompt = runClaudePromptMock.mock.calls[1]?.[0] as string;
    expect(secondPrompt.toLowerCase()).toContain('cut off'); // reask instruction was appended
  });

  it('flag ON: persistent truncation fails closed with a truncated error, never a false all-clear', async () => {
    process.env.SHOR_STRUCTURED_REPAIR = '1';
    runClaudePromptMock.mockResolvedValue({
      success: true,
      duration: 1,
      result: '{"id":"a", "x": "cut o',
      stop_reason: 'max_tokens',
    });

    const res = await runStructured({ ...CORE, validator: objValidator, maxRepairAttempts: 1 });

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error('expected failure');
    expect(res.error).toContain('truncated');
  });
});
