import { expect, test } from 'bun:test';

import {
  createDefaultSecurityAuditReport,
  createSecurityAuditCatalog,
  createSecurityAuditProfile,
  runSecurityAudit,
  serializeSecurityAuditReport,
} from '../src/index.js';

test('default security audit is deterministic and explicitly incomplete', () => {
  const first = serializeSecurityAuditReport(createDefaultSecurityAuditReport());
  const second = serializeSecurityAuditReport(createDefaultSecurityAuditReport());

  expect(first).toBe(second);
  const report = JSON.parse(first) as {
    results: { outcome: string; coverage: string }[];
    coverage: { osi: { 1: { unsupported: number } } };
  };
  expect(report.results).toHaveLength(17);
  expect(
    report.results.every(
      (result) => result.outcome === 'unknown' && result.coverage === 'unsupported',
    ),
  ).toBe(true);
  expect(report.coverage.osi[1].unsupported).toBe(1);
});

test('evidence-backed observations are attributed without inflating cross-layer coverage', () => {
  const report = runSecurityAudit(createSecurityAuditCatalog(), createSecurityAuditProfile(), [
    {
      controlId: 'osi4-service-exposure',
      applicability: 'applicable',
      coverage: 'implemented',
      outcome: 'warning',
      severity: 'medium',
      confidence: 'high',
      evidence: [
        {
          id: 'listener-summary',
          kind: 'socket-summary',
          summary: 'Redacted listener metadata was observed.',
          collectedAt: '2026-11-18T00:00:00.000Z',
          redacted: true,
        },
      ],
    },
  ]);

  expect(report.coverage.osi[4].implemented).toBe(1);
  expect(report.coverage.osi[3].implemented).toBe(0);
  expect(
    report.results.find((result) => result.control.id === 'osi4-service-exposure')?.outcome,
  ).toBe('warning');
});

test('audit rejects unknown or duplicate observations', () => {
  const controls = createSecurityAuditCatalog();
  const profile = createSecurityAuditProfile();
  const observation = {
    controlId: 'osi1-physical-interface-inventory',
    applicability: 'applicable' as const,
    coverage: 'supported' as const,
    outcome: 'unknown' as const,
    severity: 'info' as const,
    confidence: 'low' as const,
    evidence: [],
  };

  expect(() => runSecurityAudit(controls, profile, [observation, observation])).toThrow(
    'Duplicate audit observations',
  );
  expect(() =>
    runSecurityAudit(controls, profile, [{ ...observation, controlId: 'missing' }]),
  ).toThrow('Unknown audit control');
});
