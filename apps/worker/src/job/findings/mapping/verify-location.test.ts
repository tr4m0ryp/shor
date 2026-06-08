// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Cite-line verification regression tests (T5).
 *
 * The non-negotiable contract is FAIL-OPEN: a missing file, no source root, no
 * line, no usable token, or any IO error returns `undefined` (NOT `false`), so a
 * verification that cannot run never demotes a finding. When it CAN run it
 * returns a concrete `true` (the asserted construct is near the cited line) or
 * `false` (a likely mis-cite).
 */

import { promises as fs } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { verifyLocation } from './verify-location.js';

const tmpDirs: string[] = [];
async function mkRoot(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'shor-verify-'));
  tmpDirs.push(dir);
  return dir;
}

afterEach(async () => {
  for (const d of tmpDirs.splice(0)) {
    await fs.rm(d, { recursive: true, force: true });
  }
});

describe('verifyLocation — fail-open (returns undefined, never throws)', () => {
  it('returns undefined when the cited file is missing', async () => {
    const root = await mkRoot();
    const result = verifyLocation({ file: 'src/does-not-exist.ts', line: 10 }, root, 'someToken|missing defense|sqli');
    expect(result).toBeUndefined();
  });

  it('returns undefined when no analyzed-source root is supplied', () => {
    expect(verifyLocation({ file: 'src/app.ts', line: 5 }, undefined, 'render|x|xss')).toBeUndefined();
  });

  it('returns undefined when there is no usable line (line 0)', async () => {
    const root = await mkRoot();
    await fs.writeFile(path.join(root, 'a.ts'), 'const x = 1;\n');
    expect(verifyLocation({ file: 'a.ts', line: 0 }, root, 'x|y|z')).toBeUndefined();
  });

  it('returns undefined when the evidence signature has no usable token', async () => {
    const root = await mkRoot();
    await fs.writeFile(path.join(root, 'a.ts'), 'const x = 1;\n');
    // Only short / stopword tokens → nothing to look for → cannot check.
    expect(verifyLocation({ file: 'a.ts', line: 1 }, root, 'the|a|of')).toBeUndefined();
  });

  it('returns undefined for a path that escapes the source root', async () => {
    const root = await mkRoot();
    expect(verifyLocation({ file: '../../etc/passwd', line: 1 }, root, 'root|x|y')).toBeUndefined();
  });

  it('returns undefined when the cited line is past the end of the file', async () => {
    const root = await mkRoot();
    await fs.writeFile(path.join(root, 'a.ts'), 'line1\nline2\n');
    expect(verifyLocation({ file: 'a.ts', line: 999 }, root, 'line1|x|y')).toBeUndefined();
  });
});

describe('verifyLocation — concrete verdicts when the check can run', () => {
  it('returns true when a token from the signature is near the cited line', async () => {
    const root = await mkRoot();
    const src = [
      'function handler(req, res) {',
      '  const html = renderTemplate(req.query.name);',
      '  res.send(html);',
      '}',
    ].join('\n');
    await fs.writeFile(path.join(root, 'view.ts'), `${src}\n`);
    // Cite line 2 (renderTemplate) — the signature names renderTemplate.
    const result = verifyLocation(
      { file: 'view.ts', line: 2 },
      root,
      'view.ts:2|no output encoding|renderTemplate reflected XSS',
    );
    expect(result).toBe(true);
  });

  it('finds the token within the ± line window, not only the exact line', async () => {
    const root = await mkRoot();
    const src = [
      'a();',
      'b();',
      'vulnerableSink(input);', // line 3
      'c();',
      'd();',
    ].join('\n');
    await fs.writeFile(path.join(root, 'x.ts'), `${src}\n`);
    // Cite line 1 but the construct is on line 3 — inside the ±3 window.
    expect(verifyLocation({ file: 'x.ts', line: 1 }, root, 'x.ts|missing|vulnerableSink')).toBe(true);
  });

  it('returns false when no signature token appears near the cited line (mis-cite)', async () => {
    const root = await mkRoot();
    const src = [
      "import { Logger } from './log';",
      'const logger = new Logger();',
      "logger.info('startup');",
      "export const VERSION = '1.0';",
    ].join('\n');
    await fs.writeFile(path.join(root, 'boot.ts'), `${src}\n`);
    // Signature names a sink that does not exist anywhere near line 4.
    const result = verifyLocation(
      { file: 'boot.ts', line: 4 },
      root,
      'boot.ts:4|no sanitization|executeRawQuery sql injection',
    );
    expect(result).toBe(false);
  });

  it('matches the trailing member of a dotted construct (obj.Build → build)', async () => {
    const root = await mkRoot();
    await fs.writeFile(
      path.join(root, 'p.ts'),
      `${['const b = new Builder();', 'b.build();', 'return b;'].join('\n')}\n`,
    );
    expect(verifyLocation({ file: 'p.ts', line: 2 }, root, 'p.ts:2|x|builder.Build() call')).toBe(true);
  });
});
