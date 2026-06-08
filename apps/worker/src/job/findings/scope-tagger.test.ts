// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from 'vitest';
import { isOutOfScopeTarget, tagScope } from './scope-tagger.js';
import type { NormalizedVuln } from './types.js';

function vuln(raw: Record<string, unknown>, over: Partial<NormalizedVuln> = {}): NormalizedVuln {
  return {
    category: 'authz',
    id: 'V1',
    raw,
    disposition: 'exploited',
    evidenceText: '',
    ...over,
  };
}

describe('scope-tagger', () => {
  it('flags the harness mock OIDC on :8090 as out of scope', () => {
    expect(isOutOfScopeTarget(vuln({ vulnerable_code_location: 'Port 8090 mock OIDC provider (BLACK-BOX)' }))).toBe(true);
  });

  it('flags a "no source in repository" location', () => {
    expect(isOutOfScopeTarget(vuln({ vulnerable_code_location: 'BLACK-BOX service, no source in repository' }))).toBe(true);
  });

  it('flags a HARNESS_ONLY reachability regardless of location', () => {
    expect(isOutOfScopeTarget(vuln({ vulnerable_code_location: 'Real.cs:10', reachability: 'HARNESS_ONLY' }))).toBe(true);
  });

  it('does NOT flag a real target file that merely contains "Mock" in its name', () => {
    // MockUserService.cs is a genuine target file — bare "mock" must not match.
    expect(isOutOfScopeTarget(vuln({ vulnerable_code_location: 'UvA.Workflow/Users/MockUserService.cs:15' }))).toBe(false);
  });

  it('demotes an exploited scaffolding finding to out_of_scope_target + in_scope=false', () => {
    const v = vuln({ vulnerable_code_location: 'mock idp :8090' });
    tagScope([v]);
    expect(v.in_scope).toBe(false);
    expect(v.disposition).toBe('out_of_scope_target');
  });

  it('leaves a genuine in-scope finding completely untouched', () => {
    const v = vuln({ vulnerable_code_location: 'UsersController.cs:46' });
    tagScope([v]);
    expect(v.in_scope).toBeUndefined();
    expect(v.disposition).toBe('exploited');
  });

  it('preserves an already-terminal screen-rejected disposition', () => {
    const v = vuln({ vulnerable_code_location: ':8090 mock oidc' }, { disposition: 'unverified_screen_rejected' });
    tagScope([v]);
    expect(v.in_scope).toBe(false);
    expect(v.disposition).toBe('unverified_screen_rejected');
  });
});
