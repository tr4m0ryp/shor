// SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025-2026 Keygraph, Inc.
// Required Notice: Shor — https://github.com/tr4m0ryp/shor
// Noncommercial use only. Selling this software or offering it as a paid or
// hosted service requires a separate commercial license. See LICENSE & NOTICE.

/**
 * Four-way authz matrix + canary body-ownership + write-delta tests (T7 / F14).
 * Contract cases: god-mode all-200 ⇒ NOT bypassed; B carries A's canary + anon denied
 * ⇒ bypassed; anon also gets it ⇒ public/dismiss; write-delta over a pre-existing
 * value ⇒ not confirmed. No secret-shaped literals — every marker is minted.
 */

import { describe, expect, it } from 'vitest';
import type { ProviderIdentity } from '../auth-provider/index.js';
import {
  bodySimilarity,
  decideAuthz,
  selectSymmetricPeers,
  type AuthzMatrixInput,
} from './authz-matrix.js';
import { bodyCarriesCanary, bodyOwner, canarySeed, mintCanary } from './canary.js';
import type { ExecOutcome } from './types.js';
import {
  decideWriteDelta,
  mintNonce,
  runWriteDelta,
  writeDeltaEnabled,
  WRITE_DELTA_ENV,
  type StepResult,
  type WriteDeltaOps,
} from './write-delta.js';

function ok(body: string, status = 200): ExecOutcome {
  return { observed: true, status, body };
}
function denied(status = 401, body = 'unauthorized'): ExecOutcome {
  return { observed: true, status, body };
}
const NOT_OBSERVED: ExecOutcome = { observed: false, reason: 'error', detail: 'transport' };

/** A→A dashboard body carrying A's canary; the `stamp` lands in a normalized field. */
function dashboard(canaryToken: string, user: string, stamp: string): string {
  return JSON.stringify({
    page: 'account dashboard',
    profile: { username: user, plan: 'member', note: canaryToken },
    updated: `2026-07-0${stamp}T10:00:0${stamp}Z`,
  });
}

describe('canary', () => {
  it('mints unique per-account tokens and detects body ownership', () => {
    const a = mintCanary('account-a');
    const b = mintCanary('account-b');
    expect(a.token).not.toBe(b.token);
    expect(a.token.startsWith('shor-cnry-')).toBe(true);
    const body = `<p>welcome ${a.token}</p>`;
    expect(bodyCarriesCanary(body, a)).toBe(true);
    expect(bodyCarriesCanary(body, b)).toBe(false);
    expect(bodyCarriesCanary(undefined, a)).toBe(false);
  });

  it('bodyOwner returns the first account whose canary appears', () => {
    const a = mintCanary('account-a');
    const b = mintCanary('account-b');
    expect(bodyOwner(`x ${b.token} y`, [a, b])?.account).toBe('account-b');
    expect(bodyOwner('nothing here', [a, b])).toBeUndefined();
  });

  it('canarySeed produces a declarative field+value', () => {
    const a = mintCanary('account-a');
    const seed = canarySeed(a, 'bio');
    expect(seed).toEqual({ account: 'account-a', field: 'bio', value: a.token });
    expect(canarySeed(a).field).toBe('note');
  });
});

describe('bodySimilarity', () => {
  it('scores identical 1 / disjoint 0 and normalizes volatile fields', () => {
    expect(bodySimilarity('the quick brown fox', 'the quick brown fox')).toBe(1);
    expect(bodySimilarity('alpha bravo charlie', 'xdelta yecho zfoxtrot')).toBe(0);
    expect(bodySimilarity('', '')).toBe(1);
    expect(bodySimilarity('alpha', '')).toBe(0);
    // Two legitimate reads differing only in a timestamp stay identical after normalize.
    expect(
      bodySimilarity('{"user":"amy","updated":"2026-07-01T10:00:00Z"}', '{"user":"amy","updated":"2026-07-02T18:22:41Z"}'),
    ).toBe(1);
  });
});

describe('decideAuthz — four-way matrix', () => {
  const A = mintCanary('account-a');
  const B = mintCanary('account-b');
  const selfSamples: ExecOutcome[] = [ok(dashboard(A.token, 'amy', '1')), ok(dashboard(A.token, 'amy', '2'))];
  /** A valid matrix (positive control OK, anon denied); each test overrides the leg it probes. */
  const matrix = (over: Partial<AuthzMatrixInput>): AuthzMatrixInput => ({
    selfToSelf: selfSamples,
    peerToTarget: NOT_OBSERVED,
    anonToTarget: denied(),
    targetCanary: A,
    peerCanary: B,
    ...over,
  });

  it('god-mode-style all-200 is NOT bypassed (peer sees its OWN data; status never decides)', () => {
    const d = decideAuthz(matrix({ peerToTarget: ok(dashboard(B.token, 'ben', '1')) }));
    expect(d.verdict).toBe('enforced');
    expect(d.reason).toBe('access_control_enforced');
    expect(d.factors.peerCarriesTargetCanary).toBe(false);
    expect(d.factors.peerCarriesOwnCanary).toBe(true);
  });

  it('B carrying A canary + anon denied ⇒ bypassed', () => {
    const d = decideAuthz(matrix({ peerToTarget: ok(dashboard(A.token, 'amy', '3')) }));
    expect(d.verdict).toBe('bypassed');
    expect(d.reason).toBe('cross_user_bypass');
    expect(d.factors.peerCarriesTargetCanary).toBe(true);
    expect(d.factors.peerWithinBand).toBe(true);
    expect(d.factors.anonReproduced).toBe(false);
  });

  it('anon also gets it ⇒ public/dismiss (enforced, not bypassed)', () => {
    const d = decideAuthz(
      matrix({ peerToTarget: ok(dashboard(A.token, 'amy', '4')), anonToTarget: ok(dashboard(A.token, 'amy', '5')) }),
    );
    expect(d.verdict).toBe('enforced');
    expect(d.reason).toBe('public_resource');
    expect(d.factors.anonReproduced).toBe(true);
  });

  it('positive control failing (A cannot show A canary) ⇒ unknown', () => {
    const forbidden = ok('{"error":"forbidden"}');
    const d = decideAuthz(matrix({ selfToSelf: [forbidden, forbidden], peerToTarget: ok(dashboard(A.token, 'amy', '6')) }));
    expect(d.verdict).toBe('unknown');
    expect(d.reason).toBe('positive_control_failed');
  });

  it('peer leg not observable ⇒ unknown (never a refutation)', () => {
    const d = decideAuthz(matrix({ peerToTarget: NOT_OBSERVED }));
    expect(d.verdict).toBe('unknown');
    expect(d.reason).toBe('peer_not_attempted');
  });

  it('a canary reflected in a dissimilar error page ⇒ not bypassed (band guard)', () => {
    // Echoes A's canary but the body is nothing like A's real resource.
    const d = decideAuthz(matrix({ peerToTarget: ok(`error: resource ${A.token} not found for this user`, 404) }));
    expect(d.factors.peerCarriesTargetCanary).toBe(true);
    expect(d.factors.peerWithinBand).toBe(false);
    expect(d.verdict).toBe('enforced');
  });
});

function identity(label: string, role?: string): ProviderIdentity {
  return {
    label,
    authenticated: true,
    principal: { label, ...(role !== undefined && { role }) },
    candidates: [],
  };
}

describe('selectSymmetricPeers', () => {
  it('picks two role-less low-priv identities', () => {
    const pair = selectSymmetricPeers([identity('identity-member-1'), identity('identity-member-2')]);
    expect(pair?.a.label).toBe('identity-member-1');
    expect(pair?.b.label).toBe('identity-member-2');
  });

  it('excludes god-mode accounts and pairs the symmetric peers', () => {
    const pair = selectSymmetricPeers([
      identity('identity-admin', 'administrator'),
      identity('identity-member-1', 'member'),
      identity('identity-member-2', 'member'),
    ]);
    expect(pair?.a.label).toBe('identity-member-1');
    expect(pair?.b.label).toBe('identity-member-2');
  });

  it('returns undefined when no symmetric pair exists', () => {
    expect(selectSymmetricPeers([identity('identity-member-1', 'member')])).toBeUndefined();
    // Different roles ⇒ not symmetric ⇒ no pair.
    expect(
      selectSymmetricPeers([identity('u1', 'editor'), identity('u2', 'viewer')]),
    ).toBeUndefined();
    // Only a god-mode account present.
    expect(selectSymmetricPeers([identity('root-user', 'owner')])).toBeUndefined();
  });
});

describe('decideWriteDelta', () => {
  const step = (observed: boolean, present: boolean): StepResult => ({ observed, present });

  it('pre-existing nonce ⇒ not_confirmed (cannot attribute the write)', () => {
    const d = decideWriteDelta({ preRead: step(true, true), write: step(true, true), readBack: step(true, true) });
    expect(d.verdict).toBe('not_confirmed');
    expect(d.reason).toBe('nonce_pre_existing');
  });

  it('fresh nonce written and read back independently ⇒ confirmed', () => {
    const d = decideWriteDelta({ preRead: step(true, false), write: step(true, true), readBack: step(true, true) });
    expect(d.verdict).toBe('confirmed');
    expect(d.reason).toBe('nonce_appeared');
  });

  it('write rejected ⇒ not_confirmed', () => {
    const d = decideWriteDelta({ preRead: step(true, false), write: step(true, false), readBack: step(false, false) });
    expect(d.verdict).toBe('not_confirmed');
    expect(d.reason).toBe('write_rejected');
  });

  it('nonce absent after an accepted write ⇒ not_confirmed', () => {
    const d = decideWriteDelta({ preRead: step(true, false), write: step(true, true), readBack: step(true, false) });
    expect(d.verdict).toBe('not_confirmed');
    expect(d.reason).toBe('nonce_absent_after_write');
  });

  it('any unobserved infra step ⇒ inconclusive (never a refutation)', () => {
    expect(decideWriteDelta({ preRead: step(false, false), write: step(true, true), readBack: step(true, true) }).verdict).toBe('inconclusive');
    expect(decideWriteDelta({ preRead: step(true, false), write: step(false, false), readBack: step(true, true) }).verdict).toBe('inconclusive');
    expect(decideWriteDelta({ preRead: step(true, false), write: step(true, true), readBack: step(false, false) }).verdict).toBe('inconclusive');
  });
});

describe('runWriteDelta', () => {
  /**
   * Ops that record call order into `calls`; each step's result is overridable. A
   * throwing step is expressed by an override that throws (for the fail-open case).
   */
  interface Steps {
    preRead?: StepResult;
    write?: StepResult | 'throw';
    readBack?: StepResult;
  }
  function tracingOps(steps: Steps = {}): { ops: WriteDeltaOps; calls: string[] } {
    const calls: string[] = [];
    const ops: WriteDeltaOps = {
      async preRead() {
        calls.push('preRead');
        return steps.preRead ?? { observed: true, present: false };
      },
      async write() {
        calls.push('write');
        if (steps.write === 'throw') throw new Error('network down');
        return steps.write ?? { observed: true, present: true };
      },
      async readBack() {
        calls.push('readBack');
        return steps.readBack ?? { observed: true, present: true };
      },
    };
    return { ops, calls };
  }

  it('is a no-op when the RoE gate is OFF (never writes)', async () => {
    const { ops, calls } = tracingOps();
    const r = await runWriteDelta(ops, { enabled: false });
    expect(r.verdict).toBe('inconclusive');
    expect(r.reason).toBe('disabled');
    expect(calls).toEqual([]);
  });

  it('runs the full ordered sequence and confirms a genuine delta', async () => {
    const { ops, calls } = tracingOps();
    const r = await runWriteDelta(ops, { enabled: true, nonce: 'shor-nonce-fixed' });
    expect(r.verdict).toBe('confirmed');
    expect(r.nonce).toBe('shor-nonce-fixed');
    expect(calls).toEqual(['preRead', 'write', 'readBack']);
  });

  it('skips the write when the pre-read finds the nonce pre-existing', async () => {
    const { ops, calls } = tracingOps({ preRead: { observed: true, present: true } });
    const r = await runWriteDelta(ops, { enabled: true });
    expect(r.verdict).toBe('not_confirmed');
    expect(r.reason).toBe('nonce_pre_existing');
    expect(calls).toEqual(['preRead']);
  });

  it('fails open when an op throws', async () => {
    const { ops } = tracingOps({ write: 'throw' });
    const r = await runWriteDelta(ops, { enabled: true });
    expect(r.verdict).toBe('inconclusive');
  });
});

describe('write-delta gate + nonce', () => {
  it('writeDeltaEnabled honors only explicit truthy flags', () => {
    expect(writeDeltaEnabled({ [WRITE_DELTA_ENV]: 'true' })).toBe(true);
    expect(writeDeltaEnabled({ [WRITE_DELTA_ENV]: '1' })).toBe(true);
    expect(writeDeltaEnabled({ [WRITE_DELTA_ENV]: 'on' })).toBe(true);
    expect(writeDeltaEnabled({ [WRITE_DELTA_ENV]: 'false' })).toBe(false);
    expect(writeDeltaEnabled({})).toBe(false);
  });

  it('mints unique nonces', () => {
    expect(mintNonce()).not.toBe(mintNonce());
    expect(mintNonce().startsWith('shor-nonce-')).toBe(true);
  });
});
