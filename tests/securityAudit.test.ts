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
        result.baseline.status === 'missing-evidence',
    ),
  ).toBe(true);
  expect(report.coverage.osi[1].unsupported).toBe(1);
});

test('only valid evidence satisfying the active baseline may pass', () => {
  const report = runSecurityAudit(createSecurityAuditCatalog(), profile, [
    observation({ evidence: [evidence()] }),
  ]);
  const result = findControl(report, controlId);

  expect(result.outcome).toBe('pass');
  expect(result.severity).toBe('info');
  expect(result.confidence).toBe('low');
  expect(result.coverage).toBe('implemented');
  expect(result.baseline).toEqual({
    profileId: profile.id,
    expectedSecureCondition:
      'No insecure exposure is evidenced by a supported read-only collector.',
    status: 'verified',
    evidenceIds: ['listener-summary'],
  });
});

test('baseline violations derive failure severity and keep cross-layer coverage primary-only', () => {
  const report = runSecurityAudit(createSecurityAuditCatalog(), profile, [
    observation({ evidence: [evidence({ baselineStatus: 'violated' })] }),
  ]);
  const result = findControl(report, controlId);

  expect(result.outcome).toBe('fail');
  expect(result.severity).toBe('medium');
  expect(report.coverage.osi[4].implemented).toBe(1);
  expect(report.coverage.osi[3].implemented).toBe(0);
});

test('missing, blocked, contradictory, and unknown applicability evidence fail closed', () => {
  const missing = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [observation({ evidence: [] })]),
    controlId,
  );
  const blocked = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
      observation({ access: 'permission-blocked', evidence: [evidence()] }),
    ]),
    controlId,
  );
  const contradictory = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
      observation({
        evidence: [
          evidence({ id: 'secure', baselineStatus: 'satisfied' }),
          evidence({ id: 'insecure', baselineStatus: 'violated' }),
        ],
      }),
    ]),
    controlId,
  );
  const unknownApplicability = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
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
  expect(contradictory).toMatchObject({ outcome: 'unknown', coverage: 'implemented' });
  expect(contradictory.baseline.status).toBe('contradictory-evidence');
  expect(unknownApplicability).toMatchObject({ outcome: 'unknown', coverage: 'implemented' });
  expect(unknownApplicability.baseline.status).toBe('applicability-unknown');
});

test('invalid evidence metadata and sensitive summaries cannot reach a passing result', () => {
  const invalidRedaction = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
      observation({ evidence: [untypedEvidence({ redacted: false })] }),
    ]),
    controlId,
  );
  const mismatchedProfile = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
      observation({ evidence: [evidence({ profileId: 'another-profile' })] }),
    ]),
    controlId,
  );
  const leakedSummary = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
      observation({ evidence: [evidence({ summary: 'token=unredacted' })] }),
    ]),
    controlId,
  );
  const invalidApplicability = findControl(
    runSecurityAudit(createSecurityAuditCatalog(), profile, [
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
  const controls = createSecurityAuditCatalog().map((control) =>
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
    runSecurityAudit(createSecurityAuditCatalog(), malformedProfile, [
      observation({ evidence: [evidence()] }),
    ]),
    controlId,
  );

  expect(result).toMatchObject({ outcome: 'unknown', coverage: 'unsupported' });
  expect(result.baseline.status).toBe('profile-incompatible');
});

test('audit rejects unknown or duplicate observations', () => {
  const item = observation({ evidence: [] });

  expect(() => runSecurityAudit(createSecurityAuditCatalog(), profile, [item, item])).toThrow(
    'Duplicate audit observations',
  );
  expect(() =>
    runSecurityAudit(createSecurityAuditCatalog(), profile, [{ ...item, controlId: 'missing' }]),
  ).toThrow('Unknown audit control');
  expect(() =>
    runSecurityAudit([{ ...createSecurityAuditCatalog()[0]!, id: ' ' }], profile, []),
  ).toThrow('Invalid audit control identifier');
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
    baselineStatus: 'satisfied',
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

/** Find a catalog result by its stable control identifier. */
function findControl(
  report: ReturnType<typeof runSecurityAudit>,
  id: string,
): ReturnType<typeof runSecurityAudit>['results'][number] {
  const result = report.results.find((candidate) => candidate.control.id === id);
  if (!result) throw new Error(`Missing result: ${id}`);
  return result;
}
