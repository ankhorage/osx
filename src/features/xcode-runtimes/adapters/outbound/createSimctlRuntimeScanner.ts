import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import type { SimctlHost, XcodeRuntime } from '../../../../types/xcodeRuntime.js';
import { inspectTreeAsync } from '../../../storage/adapters/outbound/inspectTreeAsync.js';

/** Create the read-only adapter for CoreSimulator runtime inventory. */
export function createSimctlRuntimeScanner(host: SimctlHost = createSimctlHost()): {
  scan(): Promise<readonly XcodeRuntime[]>;
} {
  return {
    async scan() {
      return await scanSimctlAsync(host);
    },
  };
}

/** Read only the supported simctl JSON inventories and normalize their relationships. */
async function scanSimctlAsync(host: SimctlHost): Promise<readonly XcodeRuntime[]> {
  const [runtimes, devices] = await Promise.all([
    host.run('xcrun', ['simctl', 'list', 'runtimes', '-j']),
    host.run('xcrun', ['simctl', 'list', 'devices', '-j']),
  ]);
  return await parseRuntimeInventoryAsync(runtimes.stdout, devices.stdout);
}

/** Parse every future runtime family and mark the newest installed version in each family. */
export async function parseRuntimeInventoryAsync(
  runtimesJson: string,
  devicesJson: string,
): Promise<readonly XcodeRuntime[]> {
  const devices = readRecord(devicesJson, 'devices');
  const parsed = readArray(runtimesJson, 'runtimes').flatMap((value) =>
    parseRuntime(value, devices),
  );
  const newest = new Map<string, string>();
  for (const runtime of parsed.filter((item) => item.available)) {
    const current = parsed.find((item) => item.identifier === newest.get(runtime.family));
    if (!current || compareRuntime(runtime, current) > 0)
      newest.set(runtime.family, runtime.identifier);
  }
  return await Promise.all(
    parsed.map(async (runtime) => ({
      ...runtime,
      allocatedBytes: runtime.path ? (await inspectTreeAsync(runtime.path)).allocatedBytes : null,
      newestInstalled: newest.get(runtime.family) === runtime.identifier,
    })),
  );
}

/** Parse a single simctl runtime and count its attached active and unavailable devices. */
function parseRuntime(value: unknown, devices: Readonly<Record<string, unknown>>): XcodeRuntime[] {
  if (!isRecord(value) || typeof value.identifier !== 'string' || typeof value.name !== 'string')
    return [];
  const related = Object.entries(devices).find(
    ([identifier]) => identifier === value.identifier,
  )?.[1];
  const entries = Array.isArray(related) ? related : [];
  return [
    {
      identifier: value.identifier,
      name: value.name,
      family: runtimeFamily(value.identifier),
      version: typeof value.version === 'string' ? value.version : '',
      build: typeof value.buildversion === 'string' ? value.buildversion : '',
      ...(typeof value.bundlePath === 'string' ? { path: value.bundlePath } : {}),
      available: value.isAvailable !== false,
      activeDeviceCount: entries.filter((device) => isRecord(device) && device.state === 'Booted')
        .length,
      unavailableDeviceCount: entries.filter(
        (device) => isRecord(device) && device.isAvailable === false,
      ).length,
      allocatedBytes: null,
      newestInstalled: false,
    },
  ];
}

/** Derive a stable family label without an allow-list. */
function runtimeFamily(identifier: string): string {
  const family = /^com\.apple\.CoreSimulator\.SimRuntime\.([^-]+)-/u.exec(identifier)?.[1];
  return family === 'iOS' ? 'iOS/iPadOS' : (family ?? 'unknown');
}

/** Compare numeric runtime versions before their build identifiers. */
function compareRuntime(left: XcodeRuntime, right: XcodeRuntime): number {
  const leftParts = left.version.split(/\D+/u).filter(Boolean).map(Number);
  const rightParts = right.version.split(/\D+/u).filter(Boolean).map(Number);
  for (let index = 0; index < Math.max(leftParts.length, rightParts.length); index += 1) {
    const difference = (leftParts.at(index) ?? 0) - (rightParts.at(index) ?? 0);
    if (difference !== 0) return difference;
  }
  return left.build.localeCompare(right.build);
}

/** Execute argument-vector simctl calls at the outer boundary. */
function createSimctlHost(): SimctlHost {
  return {
    async run(command, args) {
      const result = await promisify(execFile)(command, [...args], {
        timeout: 60_000,
        maxBuffer: 4_000_000,
      });
      return { stdout: result.stdout };
    },
  };
}

/** Read a required JSON array fail-closed. */
function readArray(json: string, key: string): readonly unknown[] {
  const value = JSON.parse(json) as unknown;
  const entry = isRecord(value) ? Object.entries(value).find(([name]) => name === key) : undefined;
  if (!entry || !Array.isArray(entry[1])) throw new Error(`simctl ${key} JSON is unavailable.`);
  return entry[1];
}

/** Read a required JSON record fail-closed. */
function readRecord(json: string, key: string): Readonly<Record<string, unknown>> {
  const value = JSON.parse(json) as unknown;
  const entry = isRecord(value) ? Object.entries(value).find(([name]) => name === key) : undefined;
  if (!entry || !isRecord(entry[1])) throw new Error(`simctl ${key} JSON is unavailable.`);
  return entry[1];
}

/** Narrow decoded JSON values. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
