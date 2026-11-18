import { expect, test } from 'bun:test';

import {
  collectMacosHostSecurityObservations,
  createMacosHostSecuritySupportMatrix,
  createSecurityAuditCatalog,
  createSecurityAuditProfile,
  runSecurityAudit,
} from '../src/index.js';
import type { MacosHostSecurityCommandRunner, SecurityAuditControl } from '../src/index.js';

const collectedAt = '2026-11-18T00:00:00.000Z';
const hardwareControlId = 'cross-layer-hardware-startup-trust';

test('collects one observation per control and separately redacts each recognized source fact', () => {
  const observations = collectMacosHostSecurityObservations(secureRunner, collectedAt);
  const hardware = findObservation(observations, hardwareControlId);

  expect(observations).toHaveLength(6);
  expect(new Set(observations.map((observation) => observation.controlId)).size).toBe(
    observations.length,
  );
  expect(hardware).toMatchObject({ access: 'available', applicability: 'applicable' });
  expect(hardware.evidence).toEqual([
    expect.objectContaining({
      id: 'sip-status',
      facts: [{ id: 'system-integrity-protection-enabled', value: true }],
    }),
    expect.objectContaining({
      id: 'authenticated-root-status',
      facts: [{ id: 'authenticated-root-enabled', value: true }],
    }),
  ]);
  expect(JSON.stringify(observations)).not.toContain('host-private-value');
  expect(
    observations
      .flatMap((observation) => observation.evidence)
      .every((evidence) => evidence.redacted && evidence.collectedAt === collectedAt),
  ).toBe(true);
});

test('integrates separately validated SIP and Authenticated Root facts through runSecurityAudit', () => {
  const report = runSecurityAudit(
    controlsWithHardwareBaseline(),
    createSecurityAuditProfile(),
    collectMacosHostSecurityObservations(secureRunner, collectedAt),
  );
  const hardware = findResult(report, hardwareControlId);

  expect(hardware).toMatchObject({ outcome: 'pass', coverage: 'implemented' });
  expect(hardware.baseline.evidenceIds).toEqual(['authenticated-root-status', 'sip-status']);
});

test('a negative Authenticated Root source fails the joint control rather than becoming ambiguous evidence', () => {
  const report = runSecurityAudit(
    controlsWithHardwareBaseline(),
    createSecurityAuditProfile(),
    collectMacosHostSecurityObservations(authenticatedRootDisabledRunner, collectedAt),
  );
  const hardware = findResult(report, hardwareControlId);

  expect(hardware).toMatchObject({ outcome: 'fail', coverage: 'implemented' });
  expect(hardware.evidence).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        id: 'authenticated-root-status',
        facts: [{ id: 'authenticated-root-enabled', value: false }],
      }),
    ]),
  );
});

test('unrecognized output, command failures, and runner errors fail closed as unknown', () => {
  const unrecognized = collectMacosHostSecurityObservations(
    unrecognizedTimeMachineRunner,
    collectedAt,
  );
  const failed = collectMacosHostSecurityObservations(unknownRunner, collectedAt);
  const throwing = collectMacosHostSecurityObservations(throwingRunner, collectedAt);

  expect(findObservation(unrecognized, 'cross-layer-backups-resilience-logging')).toMatchObject({
    applicability: 'unknown',
    access: 'available',
    evidence: [],
  });
  for (const observations of [failed, throwing])
    expect(observations).toEqual(
      expect.arrayContaining([expect.objectContaining({ applicability: 'unknown', evidence: [] })]),
    );
});

test('does not infer a Time Machine destination from empty output and preserves an explicit negative state', () => {
  const empty = findObservation(
    collectMacosHostSecurityObservations(unrecognizedTimeMachineRunner, collectedAt),
    'cross-layer-backups-resilience-logging',
  );
  const noDestination = findObservation(
    collectMacosHostSecurityObservations(noTimeMachineDestinationRunner, collectedAt),
    'cross-layer-backups-resilience-logging',
  );

  expect(empty.evidence).toEqual([]);
  expect(noDestination.evidence[0]?.facts).toEqual([
    { id: 'time-machine-destination-reported', value: false },
  ]);
});

test('records permission denials and unavailable bounded-command outcomes as unknown evidence states', () => {
  const blocked = collectMacosHostSecurityObservations(permissionBlockedRunner, collectedAt);
  const unavailable = collectMacosHostSecurityObservations(unknownRunner, collectedAt);

  expect(blocked.every((observation) => observation.access === 'permission-blocked')).toBe(true);
  expect(blocked.every((observation) => observation.evidence.length === 0)).toBe(true);
  expect(unavailable.every((observation) => observation.access === 'available')).toBe(true);
  expect(unavailable.every((observation) => observation.evidence.length === 0)).toBe(true);
});

test('MDM enrollment is recorded as a fact but cannot become a compliance pass without a control baseline', () => {
  const report = runSecurityAudit(
    createSecurityAuditCatalog(),
    createSecurityAuditProfile(),
    collectMacosHostSecurityObservations(secureRunner, collectedAt),
  );
  const enterprise = findResult(report, 'cross-layer-enterprise-policy');

  expect(enterprise).toMatchObject({ outcome: 'unknown', coverage: 'unsupported' });
  expect(enterprise.baseline.status).toBe('profile-incompatible');
  expect(JSON.stringify(enterprise)).not.toContain('compliance pass');
});

test('support matrix covers every requested security area without asserting certification', () => {
  const matrix = createMacosHostSecuritySupportMatrix();
  const areas = new Set(matrix.map((entry) => entry.area));

  expect(areas).toEqual(
    new Set([
      'Hardware and startup',
      'Disk and data',
      'Identity and access',
      'Privacy',
      'Integrity',
      'Updates',
      'Development',
      'Resilience',
      'Enterprise',
    ]),
  );
  expect(matrix.some((entry) => entry.support === 'unknown')).toBe(true);
  expect(matrix.some((entry) => entry.support === 'unsupported')).toBe(true);
  expect(
    matrix.every((entry) => entry.sourceReference.startsWith('https://support.apple.com/')),
  ).toBe(true);
  expect(JSON.stringify(matrix)).not.toContain('certified');
});

/** Return recognized benign command output for each fixed collector command without exposing host data. */
const secureRunner: MacosHostSecurityCommandRunner = (executable, arguments_) => {
  const outputByCommand: Readonly<Record<string, string>> = {
    '/usr/bin/csrutil status': 'System Integrity Protection status: enabled.\n',
    '/usr/bin/csrutil authenticated-root status': 'Authenticated Root status: enabled.\n',
    '/usr/bin/fdesetup status': 'FileVault is On.\n',
    '/usr/sbin/sysadminctl -guestAccount status': 'Guest account is disabled.\n',
    '/usr/sbin/spctl --status': 'assessments enabled\n',
    '/usr/bin/tmutil destinationinfo': 'Name          : encrypted-backup\n',
    '/usr/bin/profiles status -type enrollment': 'MDM enrollment: Yes\n',
  };
  return {
    kind: 'completed',
    exitCode: 0,
    output: `${outputByCommand[[executable, ...arguments_].join(' ')] ?? ''}host-private-value`,
  };
};

/** Return a deliberate negative Authenticated Root condition while retaining other observable conditions. */
const authenticatedRootDisabledRunner: MacosHostSecurityCommandRunner = (executable, arguments_) =>
  executable === '/usr/bin/csrutil' && arguments_.join(' ') === 'authenticated-root status'
    ? { kind: 'completed', exitCode: 0, output: 'Authenticated Root status: disabled.\n' }
    : secureRunner(executable, arguments_);

/** Model a successful but unrecognized output, which must not create a negative fact. */
const unrecognizedTimeMachineRunner: MacosHostSecurityCommandRunner = (executable, arguments_) =>
  executable === '/usr/bin/tmutil'
    ? { kind: 'completed', exitCode: 0, output: '' }
    : secureRunner(executable, arguments_);

/** Model an explicit, recognized absence of configured Time Machine destinations. */
const noTimeMachineDestinationRunner: MacosHostSecurityCommandRunner = (executable, arguments_) =>
  executable === '/usr/bin/tmutil'
    ? { kind: 'completed', exitCode: 0, output: 'No destinations configured.\n' }
    : secureRunner(executable, arguments_);

/** Model bounded spawn, timeout, or output-limit outcomes without exposing an implementation error. */
const unknownRunner: MacosHostSecurityCommandRunner = () => ({ kind: 'unknown' });

/** Model a runner exception, which the collector must normalize to unknown rather than throw. */
const throwingRunner: MacosHostSecurityCommandRunner = () => {
  throw new Error('host-private-value');
};

/** Model an explicit macOS authorization denial without passing a protected error through the report. */
const permissionBlockedRunner: MacosHostSecurityCommandRunner = () => ({
  kind: 'completed',
  exitCode: 1,
  output: 'Operation not permitted\n',
});

/** Add a test-only baseline to the owning control for an end-to-end engine evaluation. */
function controlsWithHardwareBaseline(): readonly SecurityAuditControl[] {
  const profile = createSecurityAuditProfile();
  return createSecurityAuditCatalog().map((control) =>
    control.id === hardwareControlId
      ? {
          ...control,
          baselines: [
            {
              profileId: profile.id,
              expectedSecureCondition: 'SIP and Authenticated Root are enabled.',
              predicate: {
                kind: 'all-boolean-facts',
                facts: [
                  { id: 'system-integrity-protection-enabled', value: true },
                  { id: 'authenticated-root-enabled', value: true },
                ],
              },
              failureSeverity: 'high',
            },
          ],
        }
      : control,
  );
}

/** Find a collected observation by stable control identifier. */
function findObservation<Observation extends { readonly controlId: string }>(
  observations: readonly Observation[],
  controlId: string,
): Observation {
  const observation = observations.find((candidate) => candidate.controlId === controlId);
  if (!observation) throw new Error(`Missing observation: ${controlId}`);
  return observation;
}

/** Find an engine result by stable control identifier. */
function findResult(
  report: ReturnType<typeof runSecurityAudit>,
  controlId: string,
): ReturnType<typeof runSecurityAudit>['results'][number] {
  const result = report.results.find((candidate) => candidate.control.id === controlId);
  if (!result) throw new Error(`Missing result: ${controlId}`);
  return result;
}
