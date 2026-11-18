import { expect, test } from 'bun:test';

import {
  collectMacosPhysicalAndLinkObservations,
  createSecurityAuditProfile,
} from '../src/index.js';

const profile = createSecurityAuditProfile();
const collectedAt = '2026-11-18T00:00:00.000Z';

test('collects passive L1/L2 source availability while redacting all host and wireless identifiers', () => {
  const observations = collectMacosPhysicalAndLinkObservations({
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

test('fails closed to unknown when passive macOS sources are unavailable', () => {
  const observations = collectMacosPhysicalAndLinkObservations({
    profile,
    collectedAt,
    runner: fixtureRunner({}),
  });

  expect(observations).toHaveLength(2);
  expect(observations.every((observation) => observation.access === 'permission-blocked')).toBe(
    true,
  );
  expect(observations.every((observation) => observation.applicability === 'unknown')).toBe(true);
});

test('does not execute macOS commands or imply support on another platform', () => {
  const observations = collectMacosPhysicalAndLinkObservations({
    profile,
    collectedAt,
    runner: {
      platform: 'linux',
      run() {
        throw new Error('must not run');
      },
    },
  });

  expect(observations.every((observation) => observation.applicability === 'not-applicable')).toBe(
    true,
  );
  expect(observations.every((observation) => observation.access === 'available')).toBe(true);
});

/** Create a deterministic, process-free macOS command fixture for collector behavior. */
function fixtureRunner(outputs: Readonly<Record<string, string>>) {
  return {
    platform: 'darwin',
    run(command: string, arguments_: readonly string[]) {
      const output = outputs[[command, ...arguments_].join(' ')];
      return output === undefined
        ? { kind: 'unavailable' as const }
        : { kind: 'available' as const, stdout: output };
    },
  };
}
