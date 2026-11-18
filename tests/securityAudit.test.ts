import { expect, test } from 'bun:test';

import {
  createDefaultSecurityAuditReport,
  createSecurityAuditCatalog,
  createSecurityAuditProfile,
  runSecurityAudit,
  serializeSecurityAuditReport,
} from '../src/index.js';
import type { SecurityAuditEvidence, SecurityAuditObservation } from '../src/index.js';

const profile = createSecurityAuditProfile();
const controlId = 'osi4-service-exposure';

test('default security audit is deterministic and explicitly incomplete', () => {
  const first = serializeSecurityAuditReport(createDefaultSecurityAuditReport());
  const second = serializeSecurityAuditReport(createDefaultSecurityAuditReport());

  expect(first).toBe(second);
  const report = JSON.parse(first) as {
    results: { outcome: string; coverage: string; baseline: { status: string } }[];
    coverage: { osi: { 1: { unsupported: number } } };
  };
  expect(report.results).toHaveLength(17);
  expect(
    report.results.every(
      (result) =>
        result.outcome === 'unknown' &&
        result.coverage === 'unsupported' &&
        result.baseline.status === 'profile-incompatible',
    ),
  ).toBe(true);
  expect(report.coverage.osi[1].unsupported).toBe(1);
});

test('only facts satisfying the control-owned baseline predicate may pass', () => {
  const report = runSecurityAudit(controlsWithPredicate(), profile, [
    observation({ evidence: [evidence()] }),
  ]);
  const result = findControl(report, controlId);

  expect(result.outcome).toBe('pass');
  expect(result.severity).toBe('info');
  expect(result.confidence).toBe('low');
  expect(result.coverage).toBe('implemented');
  expect(result.baseline).toEqual({
    profileId: profile.id,
    expectedSecureCondition: 'No externally reachable TCP listeners were observed.',
    status: 'verified',
    evidenceIds: ['listener-summary'],
  });
});

test('catalog controls stay unsupported when no control-specific collector and predicate exist', () => {
  const controls = createSecurityAuditCatalog();
  const report = runSecurityAudit(
    controls,
    profile,
    controls.map((control) => ({
      controlId: control.id,
      applicability: 'applicable' as const,
      access: 'available' as const,
      evidence: [
        {
          ...evidence(),
          id: `${control.id}-generic-affirmation`,
          controlId: control.id,
          facts: [{ id: 'secure-condition-observed', value: true }],
        },
      ],
    })),
  );

  expect(controls.every((control) => control.baselines.length === 0)).toBe(true);
  expect(
    report.results.every(
      (result) =>
        result.outcome === 'unknown' &&
        result.coverage === 'unsupported' &&
        result.baseline.status === 'profile-incompatible',
    ),
  ).toBe(true);
});

test('baseline violations derive failure severity and keep cross-layer coverage primary-only', () => {
  const report = runSecurityAudit(controlsWithPredicate(), profile, [
    observation({
      evidence: [evidence({ facts: [{ id: 'no-external-tcp-listeners', value: false }] })],
    }),
  ]);
  const result = findControl(report, controlId);

  expect(result.outcome).toBe('fail');
  expect(result.severity).toBe('medium');
  expect(report.coverage.osi[4].implemented).toBe(1);
  expect(report.coverage.osi[3].implemented).toBe(0);
});

test('missing, blocked, contradictory, and unknown applicability evidence fail closed', () => {
  const missing = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [observation({ evidence: [] })]),
    controlId,
  );
  const blocked = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ access: 'permission-blocked', evidence: [evidence()] }),
    ]),
    controlId,
  );
  const incomplete = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ access: 'incomplete', evidence: [evidence()] }),
    ]),
    controlId,
  );
  const contradictory = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({
        evidence: [
          evidence({ id: 'secure', facts: [{ id: 'no-external-tcp-listeners', value: true }] }),
          evidence({ id: 'insecure', facts: [{ id: 'no-external-tcp-listeners', value: false }] }),
        ],
      }),
    ]),
    controlId,
  );
  const unknownApplicability = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ applicability: 'unknown', evidence: [evidence()] }),
    ]),
    controlId,
  );

  expect(missing).toMatchObject({ outcome: 'unknown', coverage: 'supported' });
  expect(missing.baseline.status).toBe('missing-evidence');
  expect(blocked).toMatchObject({
    outcome: 'unknown',
    coverage: 'permission-blocked',
    evidence: [],
  });
  expect(blocked.baseline.status).toBe('inaccessible-evidence');
  expect(incomplete).toMatchObject({ outcome: 'unknown', coverage: 'incomplete', evidence: [] });
  expect(incomplete.baseline.status).toBe('incomplete-evidence');
  expect(contradictory).toMatchObject({ outcome: 'unknown', coverage: 'implemented' });
  expect(contradictory.baseline.status).toBe('contradictory-evidence');
  expect(unknownApplicability).toMatchObject({ outcome: 'unknown', coverage: 'implemented' });
  expect(unknownApplicability.baseline.status).toBe('applicability-unknown');
});

test('invalid evidence metadata and sensitive summaries cannot reach a passing result', () => {
  const invalidRedaction = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ evidence: [untypedEvidence({ redacted: false })] }),
    ]),
    controlId,
  );
  const mismatchedProfile = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ evidence: [evidence({ profileId: 'another-profile' })] }),
    ]),
    controlId,
  );
  const leakedSummary = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ evidence: [evidence({ summary: 'token=unredacted' })] }),
    ]),
    controlId,
  );
  const invalidApplicability = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      untypedObservation({ applicability: 'unrecognised' }),
    ]),
    controlId,
  );

  for (const result of [invalidRedaction, mismatchedProfile, leakedSummary, invalidApplicability]) {
    expect(result).toMatchObject({ outcome: 'unknown', coverage: 'supported' });
    expect(result.baseline.status).toBe('invalid-evidence');
    expect(result.evidence).toEqual([]);
  }
});

test('a profile without a control baseline is incompatible rather than implicitly passing', () => {
  const controls = controlsWithPredicate().map((control) =>
    control.id === controlId ? { ...control, baselines: [] } : control,
  );
  const result = findControl(
    runSecurityAudit(controls, profile, [observation({ evidence: [evidence()] })]),
    controlId,
  );

  expect(result).toMatchObject({ outcome: 'unknown', coverage: 'unsupported' });
  expect(result.baseline.status).toBe('profile-incompatible');
});

test('a malformed active profile is incompatible rather than evaluated by a lookalike baseline', () => {
  const malformedProfile = { ...profile, version: '2' };
  const result = findControl(
    runSecurityAudit(controlsWithPredicate(), malformedProfile, [
      observation({ evidence: [evidence()] }),
    ]),
    controlId,
  );

  expect(result).toMatchObject({ outcome: 'unknown', coverage: 'unsupported' });
  expect(result.baseline.status).toBe('profile-incompatible');
});

test('an incomplete baseline predicate cannot claim implemented coverage', () => {
  const controls = controlsWithPredicate().map((control) =>
    control.id === controlId
      ? {
          ...control,
          baselines: control.baselines.map((baseline) => ({
            ...baseline,
            predicate: { kind: 'all-boolean-facts' as const, facts: [] },
          })),
        }
      : control,
  );
  const result = findControl(
    runSecurityAudit(controls, profile, [observation({ evidence: [evidence()] })]),
    controlId,
  );

  expect(result).toMatchObject({ outcome: 'unknown', coverage: 'unsupported', evidence: [] });
  expect(result.baseline.status).toBe('profile-incompatible');
});

test('malformed observations fail closed without aborting the remaining audit', () => {
  const item = observation({ evidence: [] });

  const duplicate = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [item, item]),
    controlId,
  );
  const unknown = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [{ ...item, controlId: 'missing' }]),
    controlId,
  );

  expect(duplicate).toMatchObject({ outcome: 'unknown', coverage: 'supported', evidence: [] });
  expect(duplicate.baseline.status).toBe('invalid-evidence');
  expect(unknown).toMatchObject({ outcome: 'unknown', coverage: 'unsupported', evidence: [] });
  expect(() =>
    runSecurityAudit([{ ...createSecurityAuditCatalog()[0]!, id: ' ' }], profile, []),
  ).toThrow('Invalid audit control identifier');
});

test('runtime JSON violations are omitted and fail closed without leaking the collector payload', () => {
  const malformedValues: readonly object[] = [
    { evidence: null },
    { evidence: {} },
    { evidence: [null] },
    { evidence: [42] },
    { evidence: [untypedEvidence({ id: null })] },
    { evidence: [untypedEvidence({ kind: {} })] },
    { evidence: [untypedEvidence({ summary: '/Users/secret/Keychain token' })] },
    {
      evidence: [untypedEvidence({ facts: [{ id: 'secure-condition-observed', value: 'true' }] })],
    },
  ];

  for (const malformed of malformedValues) {
    const result = findControl(
      runSecurityAudit(controlsWithPredicate(), profile, [untypedObservation(malformed)]),
      controlId,
    );
    expect(result).toMatchObject({ outcome: 'unknown', coverage: 'supported', evidence: [] });
    expect(result.baseline.status).toBe('invalid-evidence');
    expect(JSON.stringify(result)).not.toContain('secret');
  }
});

test('a collector baseline assertion without predicate facts remains unknown', () => {
  const result = findControl(
    runSecurityAudit(controlsWithPredicate(), profile, [
      observation({ evidence: [untypedEvidence({ baselineStatus: 'satisfied', facts: [] })] }),
    ]),
    controlId,
  );

  expect(result).toMatchObject({ outcome: 'unknown', coverage: 'supported', evidence: [] });
  expect(result.baseline.status).toBe('invalid-evidence');
});

/** Construct a collector observation with only engine-owned evaluation fields omitted. */
function observation(overrides: Partial<SecurityAuditObservation> = {}): SecurityAuditObservation {
  return {
    controlId,
    applicability: 'applicable',
    access: 'available',
    evidence: [],
    ...overrides,
  };
}

/** Construct redacted baseline evidence for the active control and profile. */
function evidence(overrides: Partial<SecurityAuditEvidence> = {}): SecurityAuditEvidence {
  return {
    id: 'listener-summary',
    controlId,
    profileId: profile.id,
    baselineVersion: profile.baseline,
    kind: 'socket-summary',
    summary: 'Redacted listener metadata was observed.',
    collectedAt: '2026-11-18T00:00:00.000Z',
    redacted: true,
    facts: [{ id: 'no-external-tcp-listeners', value: true }],
    ...overrides,
  };
}

/** Model malformed adapter JSON at the public runtime boundary. */
function untypedEvidence(value: object): SecurityAuditEvidence {
  return JSON.parse(JSON.stringify({ ...evidence(), ...value })) as SecurityAuditEvidence;
}

/** Model malformed collector observations at the public runtime boundary. */
function untypedObservation(value: object): SecurityAuditObservation {
  return JSON.parse(
    JSON.stringify({ ...observation({ evidence: [evidence()] }), ...value }),
  ) as SecurityAuditObservation;
}

/** Add a concrete test-only policy so catalog controls remain unsupported without collectors. */
function controlsWithPredicate() {
  return createSecurityAuditCatalog().map((control) =>
    control.id === controlId
      ? {
          ...control,
          baselines: [
            {
              profileId: profile.id,
              expectedSecureCondition: 'No externally reachable TCP listeners were observed.',
              predicate: {
                kind: 'all-boolean-facts' as const,
                facts: [{ id: 'no-external-tcp-listeners', value: true }],
              },
              failureSeverity: 'medium' as const,
            },
          ],
        }
      : control,
  );
}

/** Find a catalog result by its stable control identifier. */
function findControl(
  report: ReturnType<typeof runSecurityAudit>,
  id: string,
): ReturnType<typeof runSecurityAudit>['results'][number] {
  const result = report.results.find((candidate) => candidate.control.id === id);
  if (!result) throw new Error(`Missing result: ${id}`);
  return result;
}
