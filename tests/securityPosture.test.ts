import { expect, test } from 'bun:test';

import {
  collectApplicationPostureObservationAsync,
  collectPresentationTrustObservationAsync,
  collectSessionExposureObservationAsync,
  collectMacosSecurityPostureObservationsAsync,
  createSecurityAuditProfile,
} from '../src/index.js';
import { createMacosSecurityCommandRunner } from '../src/features/security-posture/adapters/createMacosSecurityCommandRunner.js';
import type { MacosSecurityCommandRunner } from '../src/features/security-posture/ports/macosSecurityCommandRunner.js';

const profile = createSecurityAuditProfile();
const collectedAt = '2026-11-18T00:00:00.000Z';

test('L5 collector retains only remote-session indicators and detects both exposure states', async () => {
  const secure = await collectSessionExposureObservationAsync(
    createRunner({
      '/usr/sbin/systemsetup -getremotelogin': output('Remote Login: Off'),
      '/usr/sbin/sharing -l': output(''),
      '/bin/launchctl print-disabled system': output(
        '"com.openssh.sshd" => true\n"com.apple.screensharing" => true\n"com.apple.remote.management" => true\n"com.apple.smbd" => true',
      ),
      '/usr/sbin/netstat -an -p tcp': output('tcp4 0 0 *.443 *.* LISTEN'),
    }),
    profile,
    collectedAt,
  );
  const exposed = await collectSessionExposureObservationAsync(
    createRunner({
      '/usr/sbin/systemsetup -getremotelogin': output('Remote Login: On'),
      '/usr/sbin/sharing -l': output('Screen Sharing\nFile Sharing'),
      '/bin/launchctl print-disabled system': output('"com.openssh.sshd" => false'),
      '/usr/sbin/netstat -an -p tcp': output('tcp4 0 0 192.0.2.4.22 *.* LISTEN'),
    }),
    profile,
    collectedAt,
  );

  expect(facts(secure)).toMatchObject({
    'remote-login-disabled': true,
    'screen-sharing-not-advertised': true,
    'remote-management-not-advertised': true,
    'file-sharing-not-advertised': true,
    'remote-sharing-services-disabled': true,
    'common-remote-listeners-not-observed': true,
  });
  expect(facts(exposed)).toMatchObject({
    'remote-login-disabled': false,
    'screen-sharing-not-advertised': false,
    'file-sharing-not-advertised': false,
    'remote-sharing-services-disabled': false,
    'common-remote-listeners-not-observed': false,
  });
  expect(JSON.stringify(exposed)).not.toContain('192.0.2.4');
});

test('L6 collector records metadata availability and proxy indicators without retaining keychain or certificate data', async () => {
  const observation = await collectPresentationTrustObservationAsync(
    createRunner({
      '/usr/bin/security dump-trust-settings -d': output('Trust Settings'),
      '/usr/bin/security list-keychains -d user': output(
        '"/Users/private/Library/Keychains/login.keychain-db"',
      ),
      '/usr/sbin/scutil --proxy': output('HTTPSEnable : 1\nHTTPProxy : intercept.example'),
    }),
    profile,
    collectedAt,
  );

  expect(facts(observation)).toMatchObject({
    'trust-settings-metadata-observable': true,
    'keychain-metadata-observable': true,
    'explicit-interception-proxy-not-configured': false,
    'certificate-validity-not-enumerated': false,
  });
  expect(JSON.stringify(observation)).not.toContain('/Users/private');
  expect(JSON.stringify(observation)).not.toContain('intercept.example');
});

test('L7 collector detects supported Gatekeeper and non-secret network and persistence metadata', async () => {
  const protectedObservation = await collectApplicationPostureObservationAsync(
    createRunner({
      '/usr/sbin/scutil --dns': output('resolver #1\n nameserver[0] : 192.0.2.53'),
      '/usr/sbin/scutil --proxy': output('HTTPEnable : 0'),
      '/usr/sbin/spctl --status': output('assessments enabled'),
      '/usr/bin/codesign -dv --verbose=2 /System/Applications/Calculator.app':
        output('Authority=Apple Root CA'),
      '/usr/sbin/spctl --assess --type execute /System/Applications/Calculator.app':
        output('accepted'),
      '/bin/launchctl print-disabled system': output('"com.example.agent" => false'),
      '/usr/sbin/netstat -an -p tcp': output('tcp4 0 0 127.0.0.1.443 *.* LISTEN'),
    }),
    profile,
    collectedAt,
  );
  const developerService = await collectApplicationPostureObservationAsync(
    createRunner({
      '/usr/sbin/scutil --dns': output('resolver #1'),
      '/usr/sbin/scutil --proxy': output('ProxyAutoConfigEnable : 1'),
      '/usr/sbin/spctl --status': output('assessments disabled'),
      '/usr/bin/codesign -dv --verbose=2 /System/Applications/Calculator.app': unavailable(),
      '/usr/sbin/spctl --assess --type execute /System/Applications/Calculator.app': unavailable(),
      '/bin/launchctl print-disabled system': output(''),
      '/usr/sbin/netstat -an -p tcp': output('tcp4 0 0 127.0.0.1.5173 *.* LISTEN'),
    }),
    profile,
    collectedAt,
  );

  expect(facts(protectedObservation)).toMatchObject({
    'resolver-metadata-observable': true,
    'application-proxy-not-configured': true,
    'gatekeeper-assessments-enabled': true,
    'system-application-signing-observable': true,
    'system-application-assessment-accepted': true,
    'system-persistence-metadata-observable': true,
    'common-developer-listeners-not-observed': true,
  });
  expect(facts(developerService)).toMatchObject({
    'application-proxy-not-configured': false,
    'gatekeeper-assessments-enabled': false,
    'common-developer-listeners-not-observed': false,
  });
  expect(JSON.stringify(protectedObservation)).not.toContain('192.0.2.53');
});

test('partial source availability remains unknown and omits facts from failed sources', async () => {
  const observation = await collectApplicationPostureObservationAsync(
    createRunner({
      '/usr/sbin/scutil --dns': output('resolver #1'),
      '/usr/sbin/scutil --proxy': unavailable(),
      '/usr/sbin/spctl --status': unavailable(),
      '/usr/bin/codesign -dv --verbose=2 /System/Applications/Calculator.app':
        output('Authority=Apple'),
      '/usr/sbin/spctl --assess --type execute /System/Applications/Calculator.app':
        output('accepted'),
      '/bin/launchctl print-disabled system': output(''),
      '/usr/sbin/netstat -an -p tcp': output('tcp4 0 0 *.443 *.* LISTEN'),
    }),
    profile,
    collectedAt,
  );

  expect(observation.applicability).toBe('unknown');
  expect(facts(observation)).not.toHaveProperty('application-proxy-not-configured');
  expect(facts(observation)).not.toHaveProperty('gatekeeper-assessments-enabled');
});

test('failed sharing and proxy sources never manufacture absence facts', async () => {
  const [sessionObservation, trustObservation] = await Promise.all([
    collectSessionExposureObservationAsync(
      createRunner({
        '/usr/sbin/systemsetup -getremotelogin': output('Remote Login: Off'),
        '/usr/sbin/sharing -l': unavailable(),
        '/bin/launchctl print-disabled system': output(''),
        '/usr/sbin/netstat -an -p tcp': unavailable(),
      }),
      profile,
      collectedAt,
    ),
    collectPresentationTrustObservationAsync(
      createRunner({
        '/usr/bin/security dump-trust-settings -d': output('Trust Settings'),
        '/usr/bin/security list-keychains -d user': output('metadata'),
        '/usr/sbin/scutil --proxy': unavailable(),
      }),
      profile,
      collectedAt,
    ),
  ]);

  expect(sessionObservation.applicability).toBe('unknown');
  expect(facts(sessionObservation)).not.toHaveProperty('screen-sharing-not-advertised');
  expect(facts(sessionObservation)).not.toHaveProperty('common-remote-listeners-not-observed');
  expect(trustObservation.applicability).toBe('unknown');
  expect(facts(trustObservation)).not.toHaveProperty('explicit-interception-proxy-not-configured');
});

test.skipIf(process.platform !== 'darwin')(
  'native command runner bounds time, output, and errors without retaining command diagnostics',
  async () => {
    const runner = createMacosSecurityCommandRunner({
      maximumOutputBytes: 8,
      timeoutMilliseconds: 50,
    });
    const [timeout, oversizedOutput, commandFailure, startFailure] = await Promise.all([
      runner.runAsync(['/bin/sh', '-c', 'sleep 1']),
      runner.runAsync(['/bin/sh', '-c', 'printf super-secret-output']),
      runner.runAsync(['/bin/sh', '-c', 'printf command-secret >&2; exit 1']),
      runner.runAsync(['/private/not-a-real-collector-secret']),
    ]);

    expect(timeout).toEqual({ exitCode: 1, stdout: '', stderr: 'Collector command timed out.' });
    expect(oversizedOutput).toEqual({
      exitCode: 1,
      stdout: '',
      stderr: 'Collector command failed.',
    });
    expect(commandFailure).toEqual({
      exitCode: 1,
      stdout: '',
      stderr: 'Collector command failed.',
    });
    expect(JSON.stringify(commandFailure)).not.toContain('command-secret');
    expect(startFailure.stdout).toBe('');
    expect(JSON.stringify(startFailure)).not.toContain('not-a-real-collector-secret');
  },
);

test('each collector is unknown when all read-only sources are unavailable', async () => {
  const unavailable = createRunner({});
  const observations = await Promise.all([
    collectSessionExposureObservationAsync(unavailable, profile, collectedAt),
    collectPresentationTrustObservationAsync(unavailable, profile, collectedAt),
    collectApplicationPostureObservationAsync(unavailable, profile, collectedAt),
  ]);

  expect(observations).toEqual([
    {
      controlId: 'osi5-remote-session-services',
      applicability: 'unknown',
      access: 'available',
      evidence: [],
    },
    {
      controlId: 'osi6-presentation-trust',
      applicability: 'unknown',
      access: 'available',
      evidence: [],
    },
    {
      controlId: 'osi7-application-network-and-persistence',
      applicability: 'unknown',
      access: 'available',
      evidence: [],
    },
  ]);
});

test.skipIf(process.platform !== 'darwin')(
  'macOS composition invokes only the three redacted L5-L7 collectors',
  async () => {
    const observations = await collectMacosSecurityPostureObservationsAsync(profile, collectedAt);

    expect(observations.map((observation) => observation.controlId)).toEqual([
      'osi5-remote-session-services',
      'osi6-presentation-trust',
      'osi7-application-network-and-persistence',
    ]);
    expect(JSON.stringify(observations)).not.toMatch(
      /\/Users\/|password|secret|token|private[ _-]?key/i,
    );
  },
);

/** Build a deterministic adapter fake without ever executing a host command in unit tests. */
function createRunner(
  outputs: Readonly<
    Record<string, { readonly exitCode: number; readonly stdout: string; readonly stderr: string }>
  >,
): MacosSecurityCommandRunner {
  return { runAsync: async (command) => outputs[command.join(' ')] ?? unavailable() };
}

/** Model a successful read-only command result. */
function output(stdout: string): {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return { exitCode: 0, stdout, stderr: '' };
}

/** Model an unavailable binary, permission boundary, or unsupported host without exposing its diagnostic text. */
function unavailable(): {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
} {
  return { exitCode: 1, stdout: '', stderr: 'unavailable' };
}

/** Convert redacted evidence into an assertion-friendly fact map. */
function facts(observation: {
  readonly evidence: readonly {
    readonly facts: readonly { readonly id: string; readonly value: boolean }[];
  }[];
}): Readonly<Record<string, boolean>> {
  return Object.fromEntries(
    observation.evidence.flatMap((evidence) => evidence.facts.map((fact) => [fact.id, fact.value])),
  );
}
