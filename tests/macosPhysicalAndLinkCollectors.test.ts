import { expect, test } from 'bun:test';

import {
  collectMacosPhysicalAndLinkObservationsAsync,
  createSecurityAuditProfile,
} from '../src/index.js';

const profile = createSecurityAuditProfile();
const collectedAt = '2026-11-18T00:00:00.000Z';

test('collects passive L1/L2 source availability while redacting all host and wireless identifiers', async () => {
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: fixtureRunner({
      '/usr/sbin/networksetup -listallhardwareports':
        'Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 00:11:22:33:44:55\n',
      '/sbin/ifconfig -l': 'lo0 en0 bridge0 vlan0',
      '/sbin/ifconfig lo0': 'status: active',
      '/sbin/ifconfig en0': 'status: active',
      '/sbin/ifconfig bridge0': 'status: active',
      '/sbin/ifconfig vlan0': 'status: active',
      '/usr/sbin/system_profiler SPUSBDataType SPThunderboltDataType SPBluetoothDataType -json':
        '{"SPBluetoothDataType":[{"controller":{"paired_devices":["Phone"]}}]}',
      '/usr/sbin/system_profiler SPAirPortDataType -json':
        '{"SPAirPortDataType":[{"spairport_security_mode":"WPA3 Personal","spairport_current_network_information":"private-network"}]}',
      '/usr/sbin/arp -an': '? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]',
    }),
  });

  expect(observations).toHaveLength(2);
  expect(observations.every((observation) => observation.applicability === 'unknown')).toBe(true);
  expect(observations.every((observation) => observation.access === 'available')).toBe(true);
  expect(JSON.stringify(observations)).not.toMatch(
    /00:11:22:33:44:55|private-network|Phone|192\.168\.1\.1|aa:bb:cc:dd:ee:ff|en0/i,
  );
  expect(observations[1]?.evidence[0]?.facts).toContainEqual({
    id: 'wifi-security-metadata-publicly-observable',
    value: true,
  });
});

test('reports missing passive macOS sources as incomplete rather than permission-blocked', async () => {
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: fixtureRunner({}),
  });

  expect(observations).toHaveLength(2);
  expect(observations.every((observation) => observation.access === 'incomplete')).toBe(true);
  expect(observations.every((observation) => observation.applicability === 'unknown')).toBe(true);
  expect(
    observations.every((observation) =>
      observation.evidence[0]?.facts.some((fact) => fact.id === 'source-missing' && fact.value),
    ),
  ).toBe(true);
});

test('distinguishes permission, timeout, and malformed JSON without exposing source output', async () => {
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: fixtureRunner({
      '/usr/sbin/networksetup -listallhardwareports': { kind: 'permission-denied' },
      '/sbin/ifconfig -l': { kind: 'timed-out' },
      '/usr/sbin/system_profiler SPUSBDataType SPThunderboltDataType SPBluetoothDataType -json': {
        kind: 'permission-denied',
      },
      '/usr/sbin/system_profiler SPAirPortDataType -json': '{not-json',
      '/usr/sbin/arp -an': { kind: 'permission-denied' },
    }),
  });

  expect(observations[0]).toMatchObject({ access: 'incomplete', applicability: 'unknown' });
  expect(observations[1]).toMatchObject({ access: 'incomplete', applicability: 'unknown' });
  expect(observations[0]?.evidence[0]?.facts).toEqual(
    expect.arrayContaining([
      { id: 'source-permission-denied', value: true },
      { id: 'source-timed-out', value: true },
    ]),
  );
  expect(observations[1]?.evidence[0]?.facts).toEqual(
    expect.arrayContaining([{ id: 'source-parse-failed', value: true }]),
  );
  expect(observations[0]?.sources).toEqual(
    expect.arrayContaining([
      { id: 'macos-passive:hardware-ports', state: 'permission-blocked', evidenceIds: [] },
      { id: 'macos-passive:interfaces', state: 'timed-out', evidenceIds: [] },
      { id: 'macos-passive:device-inventory', state: 'permission-blocked', evidenceIds: [] },
    ]),
  );
  expect(observations[1]?.sources).toEqual(
    expect.arrayContaining([
      { id: 'macos-passive:airport-metadata', state: 'parse-invalid', evidenceIds: [] },
      { id: 'macos-passive:neighbors', state: 'permission-blocked', evidenceIds: [] },
    ]),
  );
  expect(JSON.stringify(observations)).not.toContain('{not-json');
});

test('bounds per-interface status probes and marks truncated inventory incomplete', async () => {
  const calls: string[] = [];
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: {
      platform: 'darwin',
      async runAsync(command, arguments_, input) {
        calls.push([command, ...arguments_, String(input?.timeoutMilliseconds ?? '')].join(' '));
        if (command === '/sbin/ifconfig' && arguments_[0] === '-l')
          return { kind: 'available' as const, stdout: 'en0 en1 en2 en3 en4 en5' };
        if (command === '/sbin/ifconfig')
          return { kind: 'available' as const, stdout: 'status: active' };
        if (command === '/usr/sbin/system_profiler')
          return { kind: 'available' as const, stdout: '{}' };
        return { kind: 'available' as const, stdout: '' };
      },
    },
  });

  expect(calls.filter((call) => call.startsWith('/sbin/ifconfig en'))).toHaveLength(4);
  expect(
    calls
      .filter((call) => call.startsWith('/sbin/ifconfig en'))
      .every((call) => call.endsWith(' 1000')),
  ).toBe(true);
  expect(observations.every((observation) => observation.access === 'incomplete')).toBe(true);
  expect(
    observations.every((observation) =>
      observation.evidence[0]?.facts.some(
        (fact) => fact.id === 'interface-inventory-complete' && !fact.value,
      ),
    ),
  ).toBe(true);
  expect(
    observations.every((observation) =>
      observation.sources?.some(
        (source) =>
          source.id === 'macos-passive:interfaces' && source.reason === 'bounded-inventory',
      ),
    ),
  ).toBe(true);
});

test('does not manufacture a bounded-inventory reason when the bounded inventory completes', async () => {
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: countingRunner([]),
  });

  expect(
    observations.every(
      (observation) =>
        !observation.sources?.some((source) => source.reason === 'bounded-inventory'),
    ),
  ).toBe(true);
});

test('marks the fixed interface inventory source parse-invalid without preserving interface names', async () => {
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: fixtureRunner({
      '/sbin/ifconfig -l': 'host-private-interface',
      '/usr/sbin/system_profiler SPUSBDataType SPThunderboltDataType SPBluetoothDataType -json':
        '{}',
      '/usr/sbin/system_profiler SPAirPortDataType -json': '{}',
      '/usr/sbin/arp -an': '',
      '/usr/sbin/networksetup -listallhardwareports': '',
    }),
  });

  expect(observations.every((observation) => observation.access === 'incomplete')).toBe(true);
  expect(
    observations.every((observation) =>
      observation.sources?.some(
        (source) => source.id === 'macos-passive:interfaces' && source.state === 'parse-invalid',
      ),
    ),
  ).toBe(true);
  expect(JSON.stringify(observations)).not.toContain('host-private-interface');
});

test('does not execute macOS commands or imply support on another platform', async () => {
  const observations = await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    runner: {
      platform: 'linux',
      async runAsync() {
        throw new Error('must not run');
      },
    },
  });

  expect(observations.every((observation) => observation.applicability === 'not-applicable')).toBe(
    true,
  );
  expect(observations.every((observation) => observation.access === 'available')).toBe(true);
});

test('executes only L1 or L2 command sources selected at the command runner boundary', async () => {
  const l1Calls: string[] = [];
  const l2Calls: string[] = [];
  await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    controlIds: new Set(['osi1-physical-interface-inventory']),
    runner: countingRunner(l1Calls),
  });
  await collectMacosPhysicalAndLinkObservationsAsync({
    profile,
    collectedAt,
    controlIds: new Set(['osi2-link-security']),
    runner: countingRunner(l2Calls),
  });

  expect(l1Calls).toContain('/usr/sbin/networksetup -listallhardwareports');
  expect(l1Calls).not.toContain('/usr/sbin/system_profiler SPAirPortDataType -json');
  expect(l1Calls).not.toContain('/usr/sbin/arp -an');
  expect(l2Calls).not.toContain('/usr/sbin/networksetup -listallhardwareports');
  expect(l2Calls).toContain('/usr/sbin/system_profiler SPAirPortDataType -json');
  expect(l2Calls).toContain('/usr/sbin/arp -an');
  expect(l1Calls.filter((call) => call === '/sbin/ifconfig -l')).toHaveLength(1);
  expect(l2Calls.filter((call) => call === '/sbin/ifconfig -l')).toHaveLength(1);
});

/** Count actual command invocations while supplying only redacted fixture output. */
function countingRunner(calls: string[]) {
  return {
    platform: 'darwin' as const,
    async runAsync(command: string, arguments_: readonly string[]) {
      calls.push([command, ...arguments_].join(' '));
      if (command === '/sbin/ifconfig' && arguments_[0] === '-l')
        return { kind: 'available' as const, stdout: 'en0' };
      if (command === '/usr/sbin/system_profiler')
        return { kind: 'available' as const, stdout: '{}' };
      return { kind: 'available' as const, stdout: '' };
    },
  };
}

/** Create a deterministic, process-free macOS command fixture for collector behavior. */
function fixtureRunner(
  outputs: Readonly<
    Record<
      string,
      string | { readonly kind: 'missing' | 'permission-denied' | 'timed-out' | 'failed' }
    >
  >,
) {
  return {
    platform: 'darwin',
    async runAsync(command: string, arguments_: readonly string[]) {
      const output = outputs[[command, ...arguments_].join(' ')];
      if (output === undefined) return { kind: 'missing' as const };
      return typeof output === 'string' ? { kind: 'available' as const, stdout: output } : output;
    },
  };
}
