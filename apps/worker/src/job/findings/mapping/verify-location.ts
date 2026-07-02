// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Cite-line verification at creation (T5).
 *
 * A deterministic, best-effort check: open the cited `file:line` in the analyzed
 * source and assert the cited line region plausibly contains the asserted
 * construct (a token / identifier drawn from the evidence signature or
 * `vulnerability_type`). Catches the `builder.Build()` / `FileSystemProvider`
 * mis-cites that point at an unrelated line.
 *
 * FAIL-OPEN is mandatory. This sets `location_verified` on a finding but must
 * NEVER block emission: any inability to check — no source root, no file, no
 * line, an IO error, or no usable token to look for — returns `undefined`
 * (caller leaves `location_verified` undefined, NOT `false`). It only ever
 * returns a concrete `true` (token found near the line) or `false` (token
 * genuinely absent from the window) when the check could actually run.
 */

import fs from 'node:fs';
import path from 'node:path';
import type { VulnerableCodeLocation } from '../types.js';

/** Lines of context to read on either side of the cited line. */
const LINE_WINDOW = 3;
/** Cap the file read so a pathological deliverable can't stall the mapper. */
const MAX_BYTES = 2_000_000;

/**
 * Resolve `file` UNDER `root`, returning `undefined` if it escapes the root
 * (absolute path, `..` traversal). Defensive: the cited path comes from agent
 * output, so we never read outside the analyzed-source tree.
 */
function resolveUnderRoot(root: string, file: string): string | undefined {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, file);
  const rel = path.relative(resolvedRoot, resolved);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return undefined;
  return resolved;
}

/**
 * Extract candidate identifier tokens from the evidence signature. Keeps
 * code-like tokens (identifiers, dotted/`::` member accesses) of length >= 3 and
 * drops pure punctuation / stopwords. Lowercased for case-insensitive matching.
 */
function candidateTokens(evidenceSignature: string): string[] {
  const raw = evidenceSignature.match(/[A-Za-z_][A-Za-z0-9_]*(?:[.:][A-Za-z0-9_]+)*/g) ?? [];
  const stop = new Set([
    'the',
    'and',
    'not',
    'for',
    'with',
    'this',
    'that',
    'see',
    'via',
    'specified',
    'analysis',
    'deliverable',
    'vulnerability',
    'type',
    'undefined',
    'null',
    'true',
    'false',
  ]);
  const out = new Set<string>();
  for (const tok of raw) {
    const lower = tok.toLowerCase();
    if (tok.length < 3) continue;
    if (stop.has(lower)) continue;
    out.add(lower);
    // Also add the trailing member of a dotted/`::` path (e.g. `obj.Build` → `build`).
    const tail = lower.split(/[.:]/).pop();
    if (tail && tail.length >= 3 && !stop.has(tail)) out.add(tail);
  }
  return [...out];
}

/**
 * Verify the cited `location` against the analyzed source.
 *
 * @returns `true`  — a token from `evidenceSignature` appears within ±{@link
 *                    LINE_WINDOW} lines of the cited line.
 *          `false` — the file/line was read but no candidate token appears in the
 *                    window (a likely mis-cite).
 *          `undefined` — the check could NOT run (no root / file / line, IO
 *                    error, or no usable token). FAIL-OPEN: caller leaves
 *                    `location_verified` undefined.
 */
export function verifyLocation(
  location: VulnerableCodeLocation,
  analyzedSourceRoot: string | undefined,
  evidenceSignature: string,
): boolean | undefined {
  if (!analyzedSourceRoot) return undefined;
  if (!location.file || location.line <= 0) return undefined;

  const tokens = candidateTokens(evidenceSignature);
  if (tokens.length === 0) return undefined;

  try {
    const abs = resolveUnderRoot(analyzedSourceRoot, location.file);
    if (!abs) return undefined;
    const stat = fs.statSync(abs);
    if (!stat.isFile() || stat.size > MAX_BYTES) return undefined;

    const lines = fs.readFileSync(abs, 'utf8').split(/\r?\n/);
    if (location.line > lines.length) return undefined;

    const start = Math.max(0, location.line - 1 - LINE_WINDOW);
    const end = Math.min(lines.length, location.line - 1 + LINE_WINDOW + 1);
    const window = lines.slice(start, end).join('\n').toLowerCase();
    if (window.trim() === '') return undefined;

    return tokens.some((t) => window.includes(t));
  } catch {
    // Any IO / decode error ⇒ fail open. Never throw, never assert `false`.
    return undefined;
  }
}
