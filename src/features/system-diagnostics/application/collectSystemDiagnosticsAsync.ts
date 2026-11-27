import type {
  SystemDiagnosticEvidence,
  SystemDiagnosticsHost,
  SystemDiagnosticsReport,
} from '../../../types/systemDiagnostics.js';

/*** Collect bounded read-only samples without interpreting missing evidence as a healthy host. */
export async function collectSystemDiagnosticsAsync(
  host: SystemDiagnosticsHost,
  scope: SystemDiagnosticScope,
): Promise<SystemDiagnosticsReport> {
  const commands = commandsFor(scope, host.platform);
  const evidence = await Promise.all(
    commands.map(async ({ command, kind, name, serialize }) => {
      const result = await host.runAsync(command);
      return {
        kind,
        name,
        output:
          result.status === 'available' ? (serialize?.(result.output) ?? result.output) : null,
        status: result.status,
        ...(result.status === 'available' ? {} : { note: unavailableNote(result.status) }),
      } satisfies SystemDiagnosticEvidence;
    }),
  );
  return { collectedAt: new Date().toISOString(), evidence, platform: host.platform };
}

export type SystemDiagnosticScope =
  'battery' | 'diagnostics' | 'health' | 'info' | 'io' | 'processes';

/*** Choose only documented macOS inspection commands and return explicit unsupported evidence elsewhere. */
function commandsFor(
  scope: SystemDiagnosticScope,
  platform: string,
): readonly {
  readonly command: readonly string[];
  readonly kind: 'sample' | 'historical';
  readonly name: string;
  readonly serialize?: (output: string) => string;
}[] {
  if (platform !== 'darwin') return unsupportedCommands(scope);
  return macosCommandsFor(scope);
}

const macosCommands = {
  battery: [
    { command: ['pmset', '-g', 'batt'], kind: 'sample', name: 'battery status' },
    { command: ['pmset', '-g', 'thermlog'], kind: 'sample', name: 'thermal status' },
  ],
  diagnostics: [
    {
      command: ['system_profiler', 'SPSoftwareDataType', 'SPHardwareDataType'],
      kind: 'sample',
      name: 'system profile',
    },
    { command: ['diskutil', 'info', '/'], kind: 'sample', name: 'root disk status' },
    { command: ['smartctl', '-H', '/dev/disk0'], kind: 'sample', name: 'SMART status' },
  ],
  health: [
    { command: ['memory_pressure'], kind: 'sample', name: 'memory pressure' },
    { command: ['sysctl', 'vm.swapusage'], kind: 'sample', name: 'swap usage' },
    { command: ['df', '-k', '/'], kind: 'sample', name: 'root filesystem capacity' },
  ],
  info: [
    {
      command: ['system_profiler', 'SPSoftwareDataType', 'SPHardwareDataType'],
      kind: 'sample',
      name: 'OS and hardware profile',
    },
  ],
  io: [{ command: ['iostat', '-w', '1', '-c', '1'], kind: 'sample', name: 'I/O sample' }],
  processes: [
    {
      command: ['ps', '-axo', 'pid,ppid,%cpu,%mem,state,comm'],
      kind: 'sample',
      name: 'process resource sample',
    },
    { command: ['launchctl', 'list'], kind: 'sample', name: 'service status sample' },
    {
      command: [
        'log',
        'show',
        '--last',
        '24h',
        '--style',
        'compact',
        '--predicate',
        'eventMessage CONTAINS[c] "crash"',
      ],
      kind: 'historical',
      name: 'crash report metadata',
      serialize: serializeCrashMetadata,
    },
  ],
} as const;

/*** Select a fixed command list without indexing host-controlled object properties. */
function macosCommandsFor(scope: SystemDiagnosticScope) {
  switch (scope) {
    case 'battery':
      return macosCommands.battery;
    case 'diagnostics':
      return macosCommands.diagnostics;
    case 'health':
      return macosCommands.health;
    case 'info':
      return macosCommands.info;
    case 'io':
      return macosCommands.io;
    case 'processes':
      return macosCommands.processes;
  }
}

/*** Preserve each requested evidence name when the host is not macOS. */
function unsupportedCommands(scope: SystemDiagnosticScope) {
  return macosCommandsFor(scope).map(({ kind, name, serialize }) => ({
    command: [] as const,
    kind,
    name,
    serialize,
  }));
}

/*** Retain only aggregate crash-event metadata so raw Unified Log messages never leave the host boundary. */
function serializeCrashMetadata(output: string): string {
  const timestamps = output
    .split('\n')
    .map(
      (line) =>
        line.match(/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?[+-]\d{4}/)?.[0] ?? null,
    )
    .filter((timestamp): timestamp is string => timestamp !== null);

  return JSON.stringify({
    firstObservedAt: timestamps[0] ?? null,
    lastObservedAt: timestamps.at(-1) ?? null,
    observedEventCount: timestamps.length,
  });
}

/*** Give unavailable sources a bounded reason without claiming a security or health conclusion. */
function unavailableNote(status: SystemDiagnosticEvidence['status']): string {
  return status === 'permission-denied'
    ? 'The host denied access to this read-only source.'
    : status === 'unsupported'
      ? 'This source is unavailable on the current host.'
      : 'This source did not produce usable evidence.';
}
