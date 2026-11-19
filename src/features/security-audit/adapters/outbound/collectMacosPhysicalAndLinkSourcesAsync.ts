import type {
  MacosSecurityAuditCommandResult as CommandResult,
  MacosSecurityAuditCommandRunner,
} from './createMacosSecurityAuditCommandRunner.js';

const maximumInterfaceStatusProbes = 4;
const interfaceStatusProbeTimeoutMilliseconds = 1_000;

export interface InterfaceStatusInventory {
  readonly results: readonly CommandResult[];
  readonly truncated: boolean;
  readonly parseFailed: boolean;
}

interface SharedSources {
  readonly interfaces: CommandResult;
  readonly interfaceStatusInventory: InterfaceStatusInventory;
  readonly deviceInventory: CommandResult;
}

export interface PhysicalSources extends SharedSources {
  readonly hardwarePorts: CommandResult;
}

export interface LinkSources extends SharedSources {
  readonly airportMetadata: CommandResult;
  readonly neighbors: CommandResult;
}

export interface MacosPhysicalAndLinkSources {
  readonly physical?: PhysicalSources;
  readonly link?: LinkSources;
}

/** Collect only the physical, link, and shared command sources requested by the selected controls. */
export async function collectMacosPhysicalAndLinkSourcesAsync(
  runner: MacosSecurityAuditCommandRunner,
  includePhysical: boolean,
  includeLink: boolean,
  signal: AbortSignal | undefined,
): Promise<MacosPhysicalAndLinkSources> {
  const shared = await collectSharedSourcesAsync(runner, signal);
  const physical = includePhysical
    ? await collectPhysicalSourcesAsync(runner, shared, signal)
    : undefined;
  const link = includeLink ? await collectLinkSourcesAsync(runner, shared, signal) : undefined;
  return { physical, link };
}

/** Query sources that are needed by both L1 and L2 controls once per collector invocation. */
async function collectSharedSourcesAsync(
  runner: MacosSecurityAuditCommandRunner,
  signal: AbortSignal | undefined,
): Promise<SharedSources> {
  const interfaces = await runCommandAsync(runner, '/sbin/ifconfig', ['-l'], signal);
  const interfaceStatusInventory = await interfaceStatusResultsAsync(runner, interfaces, signal);
  const deviceInventory = await runCommandAsync(
    runner,
    '/usr/sbin/system_profiler',
    ['SPUSBDataType', 'SPThunderboltDataType', 'SPBluetoothDataType', '-json'],
    signal,
  );
  return { interfaces, interfaceStatusInventory, deviceInventory };
}

/** Query only the hardware-port source that belongs exclusively to the physical control. */
async function collectPhysicalSourcesAsync(
  runner: MacosSecurityAuditCommandRunner,
  shared: SharedSources,
  signal: AbortSignal | undefined,
): Promise<PhysicalSources> {
  return {
    ...shared,
    hardwarePorts: await runCommandAsync(
      runner,
      '/usr/sbin/networksetup',
      ['-listallhardwareports'],
      signal,
    ),
  };
}

/** Query only wireless and neighbor metadata that belongs exclusively to the link control. */
async function collectLinkSourcesAsync(
  runner: MacosSecurityAuditCommandRunner,
  shared: SharedSources,
  signal: AbortSignal | undefined,
): Promise<LinkSources> {
  const airportMetadata = await runCommandAsync(
    runner,
    '/usr/sbin/system_profiler',
    ['SPAirPortDataType', '-json'],
    signal,
  );
  const neighbors = await runCommandAsync(runner, '/usr/sbin/arp', ['-an'], signal);
  return { ...shared, airportMetadata, neighbors };
}

/** Query link state only for kernel-reported interface names and retain no interface names in evidence. */
async function interfaceStatusResultsAsync(
  runner: MacosSecurityAuditCommandRunner,
  interfaces: CommandResult,
  signal: AbortSignal | undefined,
): Promise<InterfaceStatusInventory> {
  if (interfaces.kind !== 'available') return { results: [], truncated: false, parseFailed: false };
  const names = interfaces.stdout
    .trim()
    .split(/\s+/)
    .filter((name) => /^[a-z]+\d+$/.test(name))
    .sort();
  const uniqueNames = [...new Set(names)];
  return {
    results: await Promise.all(
      uniqueNames
        .slice(0, maximumInterfaceStatusProbes)
        .map((name) =>
          runCommandAsync(
            runner,
            '/sbin/ifconfig',
            [name],
            signal,
            interfaceStatusProbeTimeoutMilliseconds,
          ),
        ),
    ),
    truncated: uniqueNames.length > maximumInterfaceStatusProbes,
    parseFailed: interfaces.stdout.trim().length > 0 && uniqueNames.length === 0,
  };
}

/** Avoid starting another local command after the audit deadline has cancelled this collector. */
async function runCommandAsync(
  runner: MacosSecurityAuditCommandRunner,
  command: string,
  arguments_: readonly string[],
  signal: AbortSignal | undefined,
  timeoutMilliseconds?: number,
): Promise<CommandResult> {
  if (signal?.aborted) return { kind: 'timed-out' };
  try {
    return await runner.runAsync(command, arguments_, { signal, timeoutMilliseconds });
  } catch {
    return { kind: 'failed' };
  }
}
