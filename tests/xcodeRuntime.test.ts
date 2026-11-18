import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createSimctlRuntimeOperations,
  parseRuntimeInventory,
} from '../src/features/xcode-runtimes/adapters/outbound/createSimctlRuntimeOperations.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import { cleanXcodeRuntimeStorageAsync } from '../src/features/xcode-runtimes/application/cleanXcodeRuntimeStorageAsync.js';
import type {
  SimctlHost,
  XcodeRuntimeDecisions,
  XcodeRuntimeOperations,
} from '../src/types/xcodeRuntime.js';

test('collects mixed Xcode decisions and both approvals before either deletion', async () => {
  const events: string[] = [];
  const result = await cleanXcodeRuntimeStorageAsync(
    xcodeOperations(events),
    xcodeDecisions(events),
  );
  expect(result.runtime.outcomes).toEqual([{ id: 'runtime', status: 'cleaned' }]);
  expect(result.unavailableDevices.status).toBe('cleaned');
  expect(events).toEqual([
    'scan',
    'report-runtime',
    'report-report-only-runtime',
    'report-devices',
    'select-runtime',
    'select-device',
    'approve-device',
    'approve-plan',
    'available',
    'revalidate-runtime',
    'execute-runtime',
    'available',
    'available',
    'revalidate-device',
    'execute-device',
    'available',
  ]);
});

test('keeps unsupported unavailable devices report-only without a device confirmation', async () => {
  const events: string[] = [];
  const operations = xcodeOperations(events, { deviceRisk: 'report-only' });
  const result = await cleanXcodeRuntimeStorageAsync(operations, xcodeDecisions(events));
  expect(result.unavailableDevices.status).toBe('skipped');
  expect(events).not.toContain('select-device');
  expect(events).toContain('execute-runtime');
  expect(events).not.toContain('execute-device');
});

test('does not delete either snapshot when the complete plan is refused', async () => {
  const events: string[] = [];
  const result = await cleanXcodeRuntimeStorageAsync(
    xcodeOperations(events),
    xcodeDecisions(events, { approvePlan: false }),
  );
  expect(result.runtime.outcomes).toEqual([]);
  expect(result.unavailableDevices.status).toBe('skipped');
  expect(events).toEqual([
    'scan',
    'report-runtime',
    'report-report-only-runtime',
    'report-devices',
    'select-runtime',
    'select-device',
    'approve-device',
    'approve-plan',
  ]);
});

test('does not delete an unavailable-device snapshot when strong device approval is aborted', async () => {
  const events: string[] = [];
  const result = await cleanXcodeRuntimeStorageAsync(
    xcodeOperations(events),
    xcodeDecisions(events, { approveDevice: false }),
  );
  expect(result.unavailableDevices.status).toBe('skipped');
  expect(events).not.toContain('execute-device');
  expect(events).toContain('execute-runtime');
});

test('reports a changed runtime snapshot without deleting either unapproved mutation target', async () => {
  const events: string[] = [];
  const result = await cleanXcodeRuntimeStorageAsync(
    xcodeOperations(events, { runtimeRevalidated: false }),
    xcodeDecisions(events),
  );
  expect(result.runtime.outcomes).toEqual([{ id: 'runtime', status: 'changed' }]);
  expect(events).not.toContain('execute-runtime');
  expect(events).toContain('execute-device');
});

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

test('reports a CoreSimulator connection failure without offering a destructive operation', async () => {
  const calls: string[] = [];
  const operations = createSimctlRuntimeOperations({
    async run(command, args) {
      calls.push(`${command} ${args.join(' ')}`);
      if (command === 'xcode-select')
        return { stdout: '/Applications/Xcode.app/Contents/Developer\n', stderr: '' };
      throw new Error('CoreSimulatorService connection became invalid.');
    },
    async freeBytes() {
      return null;
    },
  });

  await expect(operations.scan()).resolves.toEqual([
    expect.objectContaining({
      id: 'xcode-runtimes',
      risk: 'report-only',
      reason: 'CoreSimulatorService connection became invalid.',
    }),
  ]);
  expect(calls).toEqual(['xcode-select -p', 'xcrun simctl help runtime']);
  expect(calls.some((call) => call.includes(' delete '))).toBeFalse();
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

test('keeps unavailable devices outside Storage-V1 while requiring their own unchanged snapshot', async () => {
  const calls: string[] = [];
  const inventories = [
    devicesJson('11111111-1111-1111-1111-111111111111'),
    devicesJson('22222222-2222-2222-2222-222222222222'),
  ];
  const inventoryIndex = { value: 0 };
  const host: SimctlHost = {
    async run(command, args) {
      const call = `${command} ${args.join(' ')}`;
      calls.push(call);
      if (command === 'xcode-select')
        return { stdout: '/Applications/Xcode.app/Contents/Developer\n', stderr: '' };
      if (args.join(' ') === 'simctl help runtime') return { stdout: 'runtime delete', stderr: '' };
      if (args.join(' ') === 'simctl help delete')
        return { stdout: 'delete unavailable', stderr: '' };
      if (args.join(' ') === 'simctl list runtimes -j')
        return { stdout: JSON.stringify({ runtimes: [] }), stderr: '' };
      if (args.join(' ') === 'simctl list devices -j') {
        const result = inventories[inventoryIndex.value] ?? inventories.at(-1)!;
        inventoryIndex.value += 1;
        return { stdout: result, stderr: '' };
      }
      return { stdout: '', stderr: '' };
    },
    async freeBytes() {
      return 100;
    },
  };
  const operations = createSimctlRuntimeOperations(host);
  const unavailable = (await operations.scan()).find(
    (candidate) => candidate.kind === 'unavailable-simulator-devices',
  );
  expect(unavailable).toBeDefined();
  if (!unavailable) throw new Error('Expected unavailable-device candidate');
  expect(unavailable.estimatedBytes).toBeNull();
  expect(unavailable.risk).toBe('safe');
  await expect(operations.execute(unavailable)).rejects.toThrow(
    'Unavailable Simulator devices require the separate explicit operation.',
  );
  const genericResult = await cleanStorageAsync(operations, {
    async select() {
      throw new Error('Storage-V1 must not select an unmeasured device operation');
    },
    async approve() {
      throw new Error('Storage-V1 must not approve an unmeasured device operation');
    },
  });
  expect(genericResult.selected).toEqual([]);
  await expect(operations.executeUnavailableDevices(unavailable)).rejects.toThrow(
    'Unavailable Simulator devices changed before deletion.',
  );
  expect(calls).not.toContain('xcrun simctl delete unavailable');
});

test('deletes only the explicitly revalidated unavailable-device snapshot', async () => {
  const calls: string[] = [];
  const host = unavailableDeviceHost(calls, devicesJson('33333333-3333-3333-3333-333333333333'));
  const operations = createSimctlRuntimeOperations(host);
  const unavailable = (await operations.scan()).find(
    (candidate) => candidate.kind === 'unavailable-simulator-devices',
  );
  if (!unavailable) throw new Error('Expected unavailable-device candidate');
  expect(await operations.revalidateUnavailableDevices(unavailable)).toBeTrue();
  await operations.executeUnavailableDevices(unavailable);
  expect(calls).toContain('xcrun simctl delete unavailable');
});

test('marks a booted runtime report-only even when runtime deletion is supported', async () => {
  const host = unavailableDeviceHost(calls(), JSON.stringify({ devices: {} }));
  const root = await realpath(await mkdtemp(join(tmpdir(), 'osx-booted-runtime-')));
  try {
    const runtimePath = join(root, 'runtime');
    await mkdir(runtimePath);
    const originalRun = host.run;
    host.run = async (command, args) => {
      if (args.join(' ') === 'simctl list runtimes -j')
        return {
          stdout: JSON.stringify({
            runtimes: [
              runtime('com.apple.CoreSimulator.SimRuntime.iOS-18-0', '18.0', '22A', runtimePath),
            ],
          }),
          stderr: '',
        };
      if (args.join(' ') === 'simctl list devices -j')
        return {
          stdout: JSON.stringify({
            devices: {
              'com.apple.CoreSimulator.SimRuntime.iOS-18-0': [
                { udid: 'booted', state: 'Booted', isAvailable: true },
              ],
            },
          }),
          stderr: '',
        };
      return await originalRun(command, args);
    };
    const candidate = (await createSimctlRuntimeOperations(host).scan()).find(
      (item) => item.kind === 'xcode-runtime',
    );
    expect(candidate?.risk).toBe('report-only');
    expect(candidate?.reason).toContain('1 booted simulator device(s)');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/** Create deterministic unavailable-device inventory JSON. */
function devicesJson(udid: string): string {
  return JSON.stringify({
    devices: {
      unavailable: [{ name: 'Old phone', udid, isAvailable: false, state: 'Shutdown' }],
    },
  });
}

/** Create a supported simctl host with a fixed device inventory. */
function unavailableDeviceHost(calls: string[], devices: string): SimctlHost {
  return {
    async run(command, args) {
      const call = `${command} ${args.join(' ')}`;
      calls.push(call);
      if (command === 'xcode-select')
        return { stdout: '/Applications/Xcode.app/Contents/Developer\n', stderr: '' };
      if (args.join(' ') === 'simctl help runtime') return { stdout: 'runtime delete', stderr: '' };
      if (args.join(' ') === 'simctl help delete')
        return { stdout: 'delete unavailable', stderr: '' };
      if (args.join(' ') === 'simctl list runtimes -j')
        return { stdout: JSON.stringify({ runtimes: [] }), stderr: '' };
      if (args.join(' ') === 'simctl list devices -j') return { stdout: devices, stderr: '' };
      return { stdout: '', stderr: '' };
    },
    async freeBytes() {
      return 100;
    },
  };
}

/** Allocate an isolated call log for deterministic fake hosts. */
function calls(): string[] {
  return [];
}

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

/** Create a mixed Xcode inventory and record every interaction with its destructive boundary. */
function xcodeOperations(
  events: string[],
  options: {
    readonly deviceRisk?: 'safe' | 'report-only';
    readonly runtimeRevalidated?: boolean;
  } = {},
): XcodeRuntimeOperations {
  const runtimeCandidate = {
    id: 'runtime',
    label: 'Older iOS runtime',
    estimatedBytes: 10,
    risk: 'safe' as const,
    reason: 'safe',
    fingerprint: 'runtime-fingerprint',
    kind: 'xcode-runtime' as const,
  };
  const reportOnlyRuntime = {
    ...runtimeCandidate,
    id: 'report-only-runtime',
    risk: 'report-only' as const,
  };
  const deviceCandidate = {
    id: 'devices',
    label: 'Unavailable Simulator devices',
    estimatedBytes: null,
    risk: options.deviceRisk ?? 'safe',
    reason: 'device cleanup',
    fingerprint: 'device-fingerprint',
    kind: 'unavailable-simulator-devices' as const,
  };
  return {
    async scan() {
      events.push('scan');
      return [runtimeCandidate, reportOnlyRuntime, deviceCandidate];
    },
    async revalidate(candidate) {
      events.push('revalidate-runtime');
      return candidate.id === runtimeCandidate.id && options.runtimeRevalidated !== false;
    },
    async execute() {
      events.push('execute-runtime');
    },
    async revalidateUnavailableDevices() {
      events.push('revalidate-device');
      return true;
    },
    async executeUnavailableDevices() {
      events.push('execute-device');
    },
    async availableBytes() {
      events.push('available');
      return 100;
    },
  };
}

/** Create deterministic user decisions while preserving the exact approval order in the event log. */
function xcodeDecisions(
  events: string[],
  options: { readonly approveDevice?: boolean; readonly approvePlan?: boolean } = {},
): XcodeRuntimeDecisions {
  return {
    reportCandidate(candidate) {
      events.push(`report-${candidate.id}`);
    },
    async selectRuntime() {
      events.push('select-runtime');
      return true;
    },
    async selectUnavailableDevices() {
      events.push('select-device');
      return true;
    },
    async approveUnavailableDevices() {
      events.push('approve-device');
      return options.approveDevice ?? true;
    },
    async approvePlan() {
      events.push('approve-plan');
      return options.approvePlan ?? true;
    },
  };
}
