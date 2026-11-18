import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { statfs } from 'node:fs/promises';
import { promisify } from 'node:util';

import type { StorageCandidate } from '../../../../types/storage.js';
import type {
  SimctlHost,
  XcodeRuntime,
  XcodeRuntimeOperations,
} from '../../../../types/xcodeRuntime.js';
import { inspectTreeAsync } from '../../../storage/adapters/outbound/inspectTreeAsync.js';

/** Create the Xcode-owned Simulator runtime cleanup boundary. */
export function createSimctlRuntimeOperations(
  host: SimctlHost = createSimctlHost(),
): XcodeRuntimeOperations {
  return {
    async scan() {
      return await scanSimctlAsync(host);
    },
    async revalidate(candidate) {
      const current = await scanSimctlAsync(host);
      return current.some((item) => sameCandidate(candidate, item));
    },
    async execute(candidate) {
      if (candidate.kind === 'unavailable-simulator-devices')
        throw new Error('Unavailable Simulator devices require the separate explicit operation.');
      if (!(await this.revalidate(candidate)))
        throw new Error('Xcode runtime changed before deletion.');
      const identifier = candidate.id.replace(/^xcode-runtime:/u, '');
      await host.run('xcrun', ['simctl', 'runtime', 'delete', identifier]);
    },
    async revalidateUnavailableDevices(candidate) {
      const current = await scanSimctlAsync(host);
      return current.some(
        (item) => item.kind === 'unavailable-simulator-devices' && sameCandidate(candidate, item),
      );
    },
    async executeUnavailableDevices(candidate) {
      if (!(await this.revalidateUnavailableDevices(candidate)))
        throw new Error('Unavailable Simulator devices changed before deletion.');
      await host.run('xcrun', ['simctl', 'delete', 'unavailable']);
    },
    async availableBytes() {
      return await host.freeBytes('/');
    },
  };
}

/** Read supported simctl capabilities and inventories before exposing any destructive action. */
async function scanSimctlAsync(host: SimctlHost): Promise<readonly StorageCandidate[]> {
  try {
    const selected = await host.run('xcode-select', ['-p']);
    const runtimeHelp = await host.run('xcrun', ['simctl', 'help', 'runtime']);
    const deleteHelp = await host.run('xcrun', ['simctl', 'help', 'delete']);
    const [runtimes, devices] = await Promise.all([
      host.run('xcrun', ['simctl', 'list', 'runtimes', '-j']),
      host.run('xcrun', ['simctl', 'list', 'devices', '-j']),
    ]);
    const runtimeDeleteSupported = /\bdelete\b/u.test(runtimeHelp.stdout);
    const unavailableDeleteSupported = /\bunavailable\b/u.test(deleteHelp.stdout);
    const inventory = parseRuntimeInventory(runtimes.stdout, devices.stdout);
    const candidates = await Promise.all(
      inventory.map(
        async (runtime) =>
          await toCandidateAsync(runtime, selected.stdout.trim(), runtimeDeleteSupported),
      ),
    );
    const unavailable = unavailableDevices(devices.stdout);
    return unavailable.length > 0
      ? [...candidates, unavailableCandidate(unavailable, unavailableDeleteSupported)]
      : candidates;
  } catch (error) {
    return [reportOnly('xcode-runtimes', 'Xcode Simulator runtimes', describeError(error))];
  }
}

/** Normalize all current and future runtime-family identifiers without an allow-list. */
export function parseRuntimeInventory(
  runtimesJson: string,
  devicesJson: string,
): readonly XcodeRuntime[] {
  const runtimes = readArray(runtimesJson, 'runtimes');
  const devices = readRecord(devicesJson, 'devices');
  const parsed = runtimes.flatMap((value) => parseRuntime(value, devices));
  const newest = new Map<string, string>();
  for (const runtime of parsed.filter((item) => item.available)) {
    const current = newest.get(runtime.family);
    const currentRuntime = parsed.find((item) => item.identifier === current);
    if (!currentRuntime || compareRuntime(runtime, currentRuntime) > 0)
      newest.set(runtime.family, runtime.identifier);
  }
  return parsed
    .map((runtime) => ({
      ...runtime,
      newestInstalled: newest.get(runtime.family) === runtime.identifier,
    }))
    .sort((left, right) => left.family.localeCompare(right.family) || compareRuntime(right, left));
}

/** Parse one official simctl runtime record, rejecting records without a stable identifier. */
function parseRuntime(value: unknown, devices: Readonly<Record<string, unknown>>): XcodeRuntime[] {
  if (!isRecord(value) || typeof value.identifier !== 'string' || typeof value.name !== 'string')
    return [];
  const { identifier } = value;
  const relatedDevices = devicesForRuntime(devices, identifier);
  const activeDeviceCount = relatedDevices.filter(
    (device) => isRecord(device) && device.state === 'Booted',
  ).length;
  const unavailableDeviceCount = relatedDevices.filter(
    (device) => isRecord(device) && device.isAvailable === false,
  ).length;
  return [
    {
      identifier,
      name: value.name,
      family: runtimeFamily(identifier),
      version: typeof value.version === 'string' ? value.version : '',
      build: typeof value.buildversion === 'string' ? value.buildversion : '',
      ...(typeof value.bundlePath === 'string' ? { path: value.bundlePath } : {}),
      available: value.isAvailable !== false,
      activeDeviceCount,
      unavailableDeviceCount,
      estimatedBytes: null,
      newestInstalled: false,
    },
  ];
}

/** Name a family from the stable Simulator runtime namespace, preserving unknown future families. */
function runtimeFamily(identifier: string): string {
  const family = /^com\.apple\.CoreSimulator\.SimRuntime\.([^-]+)-/u.exec(identifier)?.[1];
  return family === 'iOS' ? 'iOS/iPadOS' : (family ?? 'unknown');
}

/** Make only verified, inactive, older installed runtime snapshots selectable. */
async function toCandidateAsync(
  runtime: XcodeRuntime,
  developerDirectory: string,
  runtimeDeleteSupported: boolean,
): Promise<StorageCandidate> {
  const inspection = runtime.path ? await inspectTreeAsync(runtime.path) : null;
  const blockers = runtimeBlockers(runtime, inspection, runtimeDeleteSupported);
  const reason =
    blockers.join('; ') || 'older installed runtime; supported simctl deletion available';
  return {
    id: `xcode-runtime:${runtime.identifier}`,
    label: `${runtime.family} ${runtime.name}${runtime.newestInstalled ? ' — NEWEST INSTALLED — KEEP' : ''}`,
    ...(runtime.path ? { path: runtime.path } : {}),
    estimatedBytes: inspection?.allocatedBytes ?? null,
    risk: blockers.length === 0 ? 'safe' : 'report-only',
    reason,
    fingerprint: runtimeFingerprint(
      runtime,
      developerDirectory,
      inspection?.fingerprint ?? undefined,
    ),
    preview: runtimePreview(runtime, developerDirectory),
    kind: 'xcode-runtime',
  };
}

/** Protect uncertain runtime state before the selection phase. */
function runtimeBlockers(
  runtime: XcodeRuntime,
  inspection: Awaited<ReturnType<typeof inspectTreeAsync>> | null,
  runtimeDeleteSupported: boolean,
): readonly string[] {
  return [
    !runtimeDeleteSupported ? 'installed simctl does not advertise runtime delete' : '',
    !runtime.available ? 'runtime unavailable' : '',
    runtime.activeDeviceCount > 0 ? `${runtime.activeDeviceCount} booted simulator device(s)` : '',
    inspection?.fingerprint === null
      ? `runtime size inspection blocked: ${inspection.blockers.join(', ')}`
      : '',
    !runtime.path ? 'runtime install location unavailable' : '',
  ].filter((blocker) => blocker !== '');
}

/** Bind the approval snapshot to runtime, Xcode selection and measured tree state. */
function runtimeFingerprint(
  runtime: XcodeRuntime,
  developerDirectory: string,
  inspection: string | undefined,
): string {
  return createHash('sha256')
    .update(JSON.stringify({ ...runtime, developerDirectory, inspection }))
    .digest('hex');
}

/** Render enough runtime state to make an informed decision. */
function runtimePreview(runtime: XcodeRuntime, developerDirectory: string): string {
  return `version ${runtime.version || 'unknown'}; build ${runtime.build || 'unknown'}; runtime ${runtime.identifier}; active devices ${runtime.activeDeviceCount}; unavailable devices ${runtime.unavailableDeviceCount}; Xcode ${developerDirectory || 'unknown'}`;
}

/** Keep unavailable-device cleanup independent from all runtime deletion decisions. */
function unavailableCandidate(devices: readonly string[], supported: boolean): StorageCandidate {
  return {
    id: 'xcode-unavailable-simulator-devices',
    label: 'Unavailable Simulator devices',
    estimatedBytes: null,
    risk: supported ? 'safe' : 'report-only',
    reason: supported
      ? 'Deletes unavailable devices and their app data only after separate final approval'
      : 'installed simctl does not advertise delete unavailable',
    fingerprint: createHash('sha256').update(devices.join('\n')).digest('hex'),
    preview: devices.join('\n'),
    kind: 'unavailable-simulator-devices',
  };
}

/** Collect unavailable devices for the separately approved simctl operation. */
function unavailableDevices(devicesJson: string): readonly string[] {
  const devices = readRecord(devicesJson, 'devices');
  return Object.values(devices).flatMap((group) =>
    Array.isArray(group)
      ? group.flatMap((device) =>
          isRecord(device) && device.isAvailable === false && typeof device.udid === 'string'
            ? [`${typeof device.name === 'string' ? device.name : 'Unnamed'} (${device.udid})`]
            : [],
        )
      : [],
  );
}

/** Compare dotted numeric versions before build identifiers. */
function compareRuntime(left: XcodeRuntime, right: XcodeRuntime): number {
  return compareVersion(left.version, right.version) || left.build.localeCompare(right.build);
}

/** Compare numeric version components without lexicographic ordering bugs. */
function compareVersion(left: string, right: string): number {
  const leftParts = left.split(/\D+/u).filter(Boolean).map(Number);
  const rightParts = right.split(/\D+/u).filter(Boolean).map(Number);
  const count = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < count; index += 1) {
    const difference = (leftParts.at(index) ?? 0) - (rightParts.at(index) ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

/** Require an unchanged full approval snapshot immediately before dispatch. */
function sameCandidate(approved: StorageCandidate, current: StorageCandidate): boolean {
  return (
    approved.id === current.id &&
    approved.risk === 'safe' &&
    current.risk === 'safe' &&
    approved.fingerprint === current.fingerprint
  );
}

/** Use argument-vector execution and filesystem accounting only at the adapter edge. */
function createSimctlHost(): SimctlHost {
  return {
    async run(command, args) {
      const result = await promisify(execFile)(command, [...args], {
        timeout: 60_000,
        maxBuffer: 4_000_000,
      });
      return { stdout: result.stdout, stderr: result.stderr };
    },
    async freeBytes(path) {
      try {
        const result = await statfs(path, { bigint: true });
        const bytes = result.bavail * result.bsize;
        return bytes <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(bytes) : null;
      } catch {
        return null;
      }
    },
  };
}

/** Parse a named JSON array fail-closed. */
function readArray(json: string, key: string): readonly unknown[] {
  const value = JSON.parse(json) as unknown;
  const entry = isRecord(value) ? Object.entries(value).find(([name]) => name === key) : undefined;
  if (!entry || !Array.isArray(entry[1])) throw new Error(`simctl ${key} JSON is unavailable.`);
  return entry[1];
}

/** Parse a named JSON record fail-closed. */
function readRecord(json: string, key: string): Readonly<Record<string, unknown>> {
  const value = JSON.parse(json) as unknown;
  const entry = isRecord(value) ? Object.entries(value).find(([name]) => name === key) : undefined;
  if (!entry || !isRecord(entry[1])) throw new Error(`simctl ${key} JSON is unavailable.`);
  return entry[1];
}

/** Find one runtime's device collection without trusting dynamic object indexing. */
function devicesForRuntime(
  devices: Readonly<Record<string, unknown>>,
  identifier: string,
): readonly unknown[] {
  const entry = Object.entries(devices).find(
    ([runtimeIdentifier]) => runtimeIdentifier === identifier,
  );
  return entry && Array.isArray(entry[1]) ? entry[1] : [];
}

/** Narrow unknown parsed JSON values. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Render system errors without leaking non-string values. */
function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Keep unavailable platform inspection report-only. */
function reportOnly(id: string, label: string, reason: string): StorageCandidate {
  return { id, label, estimatedBytes: null, risk: 'report-only', reason, fingerprint: '' };
}
