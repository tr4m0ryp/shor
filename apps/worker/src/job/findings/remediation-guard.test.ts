// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

import { describe, expect, it } from 'vitest';
import { flagBoilerplateRemediation, isBoilerplateRemediation } from './remediation-guard.js';
import type { FindingRecord } from './types.js';

describe('remediation-guard', () => {
  it('flags the mapper "missing defense" template', () => {
    expect(
      isBoilerplateRemediation(
        'Apply the missing defense: validate the token audience. See the attack-surface deliverable for the context-correct fix prompt.',
      ),
    ).toBe(true);
  });

  it('flags the mapper "context-correct" template', () => {
    expect(
      isBoilerplateRemediation('Apply the context-correct ssrf defense; see the attack-surface deliverable for the fix prompt.'),
    ).toBe(true);
  });

  it('flags an empty/whitespace remediation as non-actionable', () => {
    expect(isBoilerplateRemediation('')).toBe(true);
    expect(isBoilerplateRemediation('   ')).toBe(true);
    expect(isBoilerplateRemediation(undefined)).toBe(true);
  });

  it('does NOT flag a real, line-specific remediation', () => {
    expect(
      isBoilerplateRemediation('Remove [AllowAnonymous] on VersionsController.cs:8 and gate POST /Versions behind EnsureAuthorizedForAction(ViewAdminTools).'),
    ).toBe(false);
  });

  it('sets remediation_boilerplate=true and counts flagged records', () => {
    const records = [
      { remediation: 'Apply the missing defense: x. See the attack-surface deliverable for the context-correct fix prompt.' },
      { remediation: 'Bind the artifact token to the requesting user and rotate the committed key.' },
    ] as FindingRecord[];
    const n = flagBoilerplateRemediation(records);
    expect(n).toBe(1);
    expect(records[0].remediation_boilerplate).toBe(true);
    expect(records[1].remediation_boilerplate).toBeUndefined();
  });
});
