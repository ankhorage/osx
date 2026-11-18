import { expect, test } from 'bun:test';

import {
  collectMacosHostSecurityObservations,
  createMacosHostSecuritySupportMatrix,
  createSecurityAuditCatalog,
  createSecurityAuditProfile,
  runSecurityAudit,
} from '../src/index.js';
import type { MacosHostSecurityCommandRunner } from '../src/index.js';

const collectedAt = '2026-11-18T00:00:00.000Z';

test('collects only redacted boolean evidence from fixed read-only Apple utilities', () => {
  const observations = collectMacosHostSecurityObservations(secureRunner, collectedAt);

  expect(observations).toHaveLength(7);
  expect(observations.every((observation) => observation.access === 'available')).toBe(true);
  expect(observations.every((observation) => observation.evidence.length === 1)).toBe(true);
  expect(JSON.stringify(observations)).not.toContain('host-private-value');
  expect(
    observations
      .flatMap((observation) => observation.evidence)
      .every((evidence) => evidence.redacted),
  ).toBe(true);
  expect(
    observations
      .flatMap((observation) => observation.evidence)
      .every((evidence) => evidence.collectedAt === collectedAt),
  ).toBe(true);
});

test('records an observed insecure state as false evidence rather than converting it into a pass', () => {
  const observations = collectMacosHostSecurityObservations(insecureGatekeeperRunner, collectedAt);
  const gatekeeper = observations.find(
    (observation) => observation.controlId === 'cross-layer-malware-integrity',
  );

  expect(gatekeeper?.evidence[0]?.facts).toEqual([
    { id: 'gatekeeper-assessments-enabled', value: false },
  ]);
  const report = runSecurityAudit(
    createSecurityAuditCatalog(),
    createSecurityAuditProfile(),
    observations,
  );
  expect(
    report.results.find((result) => result.control.id === gatekeeper?.controlId)?.outcome,
  ).toBe('unknown');
});

test('treats access denials and unavailable commands as unknown evidence states', () => {
  const blocked = collectMacosHostSecurityObservations(permissionBlockedRunner, collectedAt);
  const unavailable = collectMacosHostSecurityObservations(unavailableRunner, collectedAt);

  expect(blocked.every((observation) => observation.access === 'permission-blocked')).toBe(true);
  expect(blocked.every((observation) => observation.evidence.length === 0)).toBe(true);
  expect(unavailable.every((observation) => observation.access === 'available')).toBe(true);
  expect(unavailable.every((observation) => observation.evidence.length === 0)).toBe(true);
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

/** Return benign command output for each fixed collector command without exposing host data. */
const secureRunner: MacosHostSecurityCommandRunner = (executable) => {
  const outputByExecutable: Readonly<Record<string, string>> = {
    '/usr/bin/csrutil':
      'System Integrity Protection status: enabled.\nAuthenticated Root status: enabled.\n',
    '/usr/bin/fdesetup': 'FileVault is On.\n',
    '/usr/sbin/sysadminctl': 'Guest account is disabled.\n',
    '/usr/sbin/spctl': 'assessments enabled\n',
    '/usr/bin/tmutil': 'Name          : encrypted-backup\n',
    '/usr/bin/profiles': 'MDM enrollment: Yes\n',
  };
  return { exitCode: 0, output: `${outputByExecutable[executable] ?? ''}host-private-value` };
};

/** Return a deliberate negative Gatekeeper condition while retaining other observable conditions. */
const insecureGatekeeperRunner: MacosHostSecurityCommandRunner = (executable, arguments_) =>
  executable === '/usr/sbin/spctl'
    ? { exitCode: 0, output: 'assessments disabled\n' }
    : secureRunner(executable, arguments_);

/** Model an explicit macOS authorization denial without passing a protected error through the report. */
const permissionBlockedRunner: MacosHostSecurityCommandRunner = () => ({
  exitCode: 1,
  output: 'Operation not permitted\n',
});

/** Model a missing or unsupported utility without treating platform absence as a secure finding. */
const unavailableRunner: MacosHostSecurityCommandRunner = () => ({ exitCode: 127, output: '' });
