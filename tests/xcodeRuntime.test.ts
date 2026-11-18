import { expect, test } from 'bun:test';

import {
  createSimctlRuntimeScanner,
  parseRuntimeInventoryAsync,
} from '../src/features/xcode-runtimes/adapters/outbound/createSimctlRuntimeScanner.js';

test('discovers runtime families, newest installed versions, sizes and device relationships', async () => {
  const runtimes = JSON.stringify({
    runtimes: [
      {
        identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-17-0',
        name: 'iOS 17.0',
        version: '17.0',
        buildversion: 'A',
      },
      {
        identifier: 'com.apple.CoreSimulator.SimRuntime.iOS-18-0',
        name: 'iOS 18.0',
        version: '18.0',
        buildversion: 'B',
      },
      {
        identifier: 'com.apple.CoreSimulator.SimRuntime.watchOS-11-0',
        name: 'watchOS 11.0',
        version: '11.0',
        buildversion: 'C',
      },
    ],
  });
  const devices = JSON.stringify({
    devices: {
      'com.apple.CoreSimulator.SimRuntime.iOS-17-0': [{ state: 'Booted' }, { isAvailable: false }],
    },
  });
  const inventory = await parseRuntimeInventoryAsync(runtimes, devices);
  expect(inventory.map((runtime) => runtime.family)).toEqual([
    'iOS/iPadOS',
    'iOS/iPadOS',
    'watchOS',
  ]);
  expect(
    inventory.filter((runtime) => runtime.newestInstalled).map((runtime) => runtime.version),
  ).toEqual(['18.0', '11.0']);
  expect(inventory[0]).toMatchObject({
    activeDeviceCount: 1,
    unavailableDeviceCount: 1,
    allocatedBytes: null,
  });
});

test('uses only read-only simctl inventory commands', async () => {
  const calls: string[] = [];
  const scanner = createSimctlRuntimeScanner({
    async run(command, args) {
      calls.push(`${command} ${args.join(' ')}`);
      return { stdout: args.includes('runtimes') ? '{"runtimes":[]}' : '{"devices":{}}' };
    },
  });
  await expect(scanner.scan()).resolves.toEqual([]);
  expect(calls).toEqual(['xcrun simctl list runtimes -j', 'xcrun simctl list devices -j']);
  expect(calls.join(' ')).not.toContain('delete');
});
