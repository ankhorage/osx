import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createSimctlRuntimeOperations,
  parseRuntimeInventory,
} from '../src/features/xcode-runtimes/adapters/outbound/createSimctlRuntimeOperations.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import type { SimctlHost } from '../src/types/xcodeRuntime.js';

test('discovers every runtime family and marks only the numeric newest installed runtime', () => {
  const runtimes = JSON.stringify({
    runtimes: [
      runtime('com.apple.CoreSimulator.SimRuntime.iOS-9-10', '9.10', '22Z2'),
      runtime('com.apple.CoreSimulator.SimRuntime.iOS-10-2', '10.2', '22A1'),
      runtime('com.apple.CoreSimulator.SimRuntime.watchOS-11-0', '11.0', '22R1'),
      runtime('com.apple.CoreSimulator.SimRuntime.tvOS-18-0', '18.0', '22J1'),
      runtime('com.apple.CoreSimulator.SimRuntime.xrOS-2-0', '2.0', '22N1'),
    ],
  });
  const inventory = parseRuntimeInventory(runtimes, JSON.stringify({ devices: {} }));
  expect(inventory.map((item) => item.family)).toEqual([
    'iOS/iPadOS',
    'iOS/iPadOS',
    'tvOS',
    'watchOS',
    'xrOS',
  ]);
  expect(inventory.filter((item) => item.newestInstalled).map((item) => item.version)).toEqual([
    '10.2',
    '18.0',
    '11.0',
    '2.0',
  ]);
});

test('collects decisions before deletion and revalidates the runtime snapshot', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osx-xcode-runtime-')));
  try {
    const oldPath = join(root, 'old');
    const currentPath = join(root, 'current');
    await Promise.all([mkdir(oldPath), mkdir(currentPath)]);
    await Promise.all([
      writeFile(join(oldPath, 'runtime'), 'old'),
      writeFile(join(currentPath, 'runtime'), 'new'),
    ]);
    const calls: string[] = [];
    const host: SimctlHost = {
      async run(command, args) {
        calls.push(`${command} ${args.join(' ')}`);
        if (command === 'xcode-select')
          return { stdout: '/Applications/Xcode.app/Contents/Developer\n', stderr: '' };
        if (args.join(' ') === 'simctl help runtime')
          return { stdout: 'runtime delete <identifier>', stderr: '' };
        if (args.join(' ') === 'simctl help delete')
          return { stdout: 'delete unavailable', stderr: '' };
        if (args.join(' ') === 'simctl list runtimes -j')
          return {
            stdout: JSON.stringify({
              runtimes: [
                runtime('com.apple.CoreSimulator.SimRuntime.iOS-17-0', '17.0', '21A', oldPath),
                runtime('com.apple.CoreSimulator.SimRuntime.iOS-18-0', '18.0', '22A', currentPath),
              ],
            }),
            stderr: '',
          };
        if (args.join(' ') === 'simctl list devices -j')
          return { stdout: JSON.stringify({ devices: {} }), stderr: '' };
        return { stdout: '', stderr: '' };
      },
      async freeBytes() {
        return 100;
      },
    };
    const result = await cleanStorageAsync(createSimctlRuntimeOperations(host), {
      async select(candidate) {
        expect(calls.some((call) => call.includes('runtime delete'))).toBeFalse();
        return candidate.id.includes('17-0');
      },
      async approve(selected) {
        expect(selected).toHaveLength(1);
        expect(calls.some((call) => call.includes('runtime delete'))).toBeFalse();
        return true;
      },
    });
    expect(result.outcomes).toEqual([
      { id: 'xcode-runtime:com.apple.CoreSimulator.SimRuntime.iOS-17-0', status: 'cleaned' },
    ]);
    expect(calls.at(-1)).toBe(
      'xcrun simctl runtime delete com.apple.CoreSimulator.SimRuntime.iOS-17-0',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/** Build a minimal official runtime JSON fixture. */
function runtime(identifier: string, version: string, buildversion: string, bundlePath?: string) {
  return {
    identifier,
    name: identifier.split('.').at(-1) ?? identifier,
    version,
    buildversion,
    isAvailable: true,
    ...(bundlePath ? { bundlePath } : {}),
  };
}
