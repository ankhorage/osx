import { expect, test } from 'bun:test';

import {
  collectMacosHostSecurityObservations,
  createMacosHostSecuritySupportMatrix,
  createSecurityAuditCatalog,
  createSecurityAuditProfile,
  runSecurityAudit,
} from '../src/index.js';
import type { MacosSecurityAuditCommandRunner, SecurityAuditControl } from '../src/index.js';

const collectedAt = '2026-11-18T00:00:00.000Z';
const profile = createSecurityAuditProfile();
const hardwareControlId = 'cross-layer-hardware-startup-trust';

test('collects SIP and Authenticated Root as separate redacted evidence sources for one observation', () => {
  const observations = collect(secureRunner);
  const hardware = findObservation(observations, hardwareControlId);
  expect(observations).toHaveLength(6);
  expect(new Set(observations.map((observation) => observation.controlId)).size).toBe(6);
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
});

test('integrates two evidence sources only through a control-owned test baseline', () => {
  const hardware = findResult(
    runSecurityAudit(controlsWithHardwareBaseline(), profile, collect(secureRunner)),
    hardwareControlId,
  );
  expect(hardware).toMatchObject({ outcome: 'pass', coverage: 'implemented' });
  expect(hardware.baseline.evidenceIds).toEqual(['authenticated-root-status', 'sip-status']);
});

test('fails the joint test baseline when Authenticated Root is explicitly disabled', () => {
  const hardware = findResult(
    runSecurityAudit(
      controlsWithHardwareBaseline(),
      profile,
      collect(authenticatedRootDisabledRunner),
    ),
    hardwareControlId,
  );
  expect(hardware).toMatchObject({ outcome: 'fail', coverage: 'implemented' });
});

test('preserves permission, failed-command, and unrecognized-output states as non-passing evidence', () => {
  const blocked = collect(permissionBlockedRunner);
  const failed = collect(failedRunner);
  const unrecognized = findObservation(
    collect(unrecognizedTimeMachineRunner),
    'cross-layer-backups-resilience-logging',
  );
  expect(blocked.every((observation) => observation.access === 'permission-blocked')).toBe(true);
  expect(failed.every((observation) => observation.access === 'incomplete')).toBe(true);
  expect(unrecognized).toMatchObject({
    access: 'available',
    applicability: 'unknown',
    evidence: [],
  });
});

test('does not infer backup encryption, recovery, or compliance from destination and enrollment facts', () => {
  const backup = findObservation(collect(secureRunner), 'cross-layer-backups-resilience-logging');
  const enterprise = findResult(
    runSecurityAudit(createSecurityAuditCatalog(), profile, collect(secureRunner)),
    'cross-layer-enterprise-policy',
  );
  expect(backup.evidence[0]?.summary).toContain('does not verify backup encryption or recovery');
  expect(enterprise).toMatchObject({ outcome: 'unknown', coverage: 'unsupported' });
  expect(JSON.stringify(enterprise)).not.toContain('compliance pass');
});

test('does not run macOS commands or claim applicability on another platform', () => {
  const observations = collect({
    platform: 'linux',
    run() {
      throw new Error('must not run');
    },
  });
  expect(observations.every((observation) => observation.applicability === 'not-applicable')).toBe(
    true,
  );
});

test('keeps unsupported and unknown support areas distinct from certification claims', () => {
  const matrix = createMacosHostSecuritySupportMatrix();

  expect(matrix.some((entry) => entry.support === 'unknown')).toBe(true);
  expect(matrix.some((entry) => entry.support === 'unsupported')).toBe(true);
  expect(JSON.stringify(matrix)).not.toContain('certified');
});

test.skipIf(process.platform !== 'darwin')(
  'uses the bounded shared macOS runner without serializing host paths or PEM markers',
  async () => {
    const { createMacosSecurityAuditCommandRunner } = await import('../src/index.js');
    const serialized = JSON.stringify(
      collectMacosHostSecurityObservations({
        runner: createMacosSecurityAuditCommandRunner(),
        profile,
        collectedAt,
      }),
    );
    expect(serialized).not.toContain(process.env.HOME ?? '');
    expect(serialized).not.toContain('BEGIN');
  },
);

/** Collect host observations with the fixed profile and deterministic collection timestamp. */
function collect(runner: MacosSecurityAuditCommandRunner) {
  return collectMacosHostSecurityObservations({ runner, profile, collectedAt });
}

/** Return recognized benign output for every fixed read-only host command. */
const secureRunner = runner({
  '/usr/bin/csrutil status': 'System Integrity Protection status: enabled.\n',
  '/usr/bin/csrutil authenticated-root status': 'Authenticated Root status: enabled.\n',
  '/usr/bin/fdesetup status': 'FileVault is On.\n',
  '/usr/sbin/sysadminctl -guestAccount status': 'Guest account is disabled.\n',
  '/usr/sbin/spctl --status': 'assessments enabled\n',
  '/usr/bin/tmutil destinationinfo': 'Name          : encrypted-backup\n',
  '/usr/bin/profiles status -type enrollment': 'MDM enrollment: Yes\n',
});

/** Return a deliberate negative Authenticated Root condition with otherwise recognized facts. */
const authenticatedRootDisabledRunner = runner({
  '/usr/bin/csrutil status': 'System Integrity Protection status: enabled.\n',
  '/usr/bin/csrutil authenticated-root status': 'Authenticated Root status: disabled.\n',
  '/usr/bin/fdesetup status': 'FileVault is On.\n',
  '/usr/sbin/sysadminctl -guestAccount status': 'Guest account is disabled.\n',
  '/usr/sbin/spctl --status': 'assessments enabled\n',
  '/usr/bin/tmutil destinationinfo': 'Name          : encrypted-backup\n',
  '/usr/bin/profiles status -type enrollment': 'MDM enrollment: Yes\n',
});

/** Model successful but semantically unknown Time Machine output. */
const unrecognizedTimeMachineRunner = runner({
  '/usr/bin/csrutil status': 'System Integrity Protection status: enabled.\n',
  '/usr/bin/csrutil authenticated-root status': 'Authenticated Root status: enabled.\n',
  '/usr/bin/fdesetup status': 'FileVault is On.\n',
  '/usr/sbin/sysadminctl -guestAccount status': 'Guest account is disabled.\n',
  '/usr/sbin/spctl --status': 'assessments enabled\n',
  '/usr/bin/tmutil destinationinfo': '',
  '/usr/bin/profiles status -type enrollment': 'MDM enrollment: Yes\n',
});

/** Model a command runner that never obtains a usable source result. */
const failedRunner: MacosSecurityAuditCommandRunner = {
  platform: 'darwin',
  run() {
    return { kind: 'failed' };
  },
};

/** Model a command runner whose every source is access-blocked. */
const permissionBlockedRunner: MacosSecurityAuditCommandRunner = {
  platform: 'darwin',
  run() {
    return { kind: 'permission-denied' };
  },
};

/** Create a deterministic process-free macOS runner fixture. */
function runner(outputs: Readonly<Record<string, string>>): MacosSecurityAuditCommandRunner {
  return {
    platform: 'darwin',
    run(command, arguments_) {
      return { kind: 'available', stdout: outputs[[command, ...arguments_].join(' ')] ?? '' };
    },
  };
}

/** Add a test-only baseline; production controls intentionally have no pass-authorizing baseline. */
function controlsWithHardwareBaseline(): readonly SecurityAuditControl[] {
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

/** Find a collected observation by its stable control identifier. */
function findObservation<Observation extends { readonly controlId: string }>(
  observations: readonly Observation[],
  controlId: string,
): Observation {
  const observation = observations.find((candidate) => candidate.controlId === controlId);
  if (!observation) throw new Error(`Missing observation: ${controlId}`);
  return observation;
}

/** Find an engine result by its stable control identifier. */
function findResult(
  report: ReturnType<typeof runSecurityAudit>,
  controlId: string,
): ReturnType<typeof runSecurityAudit>['results'][number] {
  const result = report.results.find((candidate) => candidate.control.id === controlId);
  if (!result) throw new Error(`Missing result: ${controlId}`);
  return result;
}
