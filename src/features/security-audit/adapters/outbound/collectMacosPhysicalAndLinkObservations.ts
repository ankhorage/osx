import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../../types/securityAudit.js';
import type {
  MacosSecurityAuditCommandResult as CommandResult,
  MacosSecurityAuditCommandRunner,
} from './createMacosSecurityAuditCommandRunner.js';

const maximumInterfaceStatusProbes = 4;
const interfaceStatusProbeTimeoutMilliseconds = 1_000;

interface CollectorInput {
  readonly runner: MacosSecurityAuditCommandRunner;
  readonly profile: SecurityAuditProfile;
  readonly collectedAt: string;
  readonly signal?: AbortSignal;
}

/*** Collect redacted, passive OSI 1 and 2 observations without exposing host identifiers or mutating macOS. */
export async function collectMacosPhysicalAndLinkObservationsAsync(
  input: CollectorInput,
): Promise<readonly SecurityAuditObservation[]> {
  if (input.runner.platform !== 'darwin') return unsupportedPlatformObservations(input);
  const sources = await collectSourcesAsync(input.runner, input.signal);
  return [physicalObservation(input, sources), linkObservation(input, sources)];
}

interface MacosPhysicalAndLinkSources {
  readonly hardwarePorts: CommandResult;
  readonly interfaces: CommandResult;
  readonly interfaceStatusInventory: InterfaceStatusInventory;
  readonly deviceInventory: CommandResult;
  readonly airportMetadata: CommandResult;
  readonly neighbors: CommandResult;
}

interface InterfaceStatusInventory {
  readonly results: readonly CommandResult[];
  readonly truncated: boolean;
  readonly parseFailed: boolean;
}

/*** Query only public, local macOS inspection commands through the injected outer boundary. */
async function collectSourcesAsync(
  runner: MacosSecurityAuditCommandRunner,
  signal: AbortSignal | undefined,
): Promise<MacosPhysicalAndLinkSources> {
  const hardwarePorts = await runCommandAsync(
    runner,
    '/usr/sbin/networksetup',
    ['-listallhardwareports'],
    signal,
  );
  const interfaces = await runCommandAsync(runner, '/sbin/ifconfig', ['-l'], signal);
  const interfaceStatusInventory = await interfaceStatusResultsAsync(runner, interfaces, signal);
  const deviceInventory = await runCommandAsync(
    runner,
    '/usr/sbin/system_profiler',
    ['SPUSBDataType', 'SPThunderboltDataType', 'SPBluetoothDataType', '-json'],
    signal,
  );
  const airportMetadata = await runCommandAsync(
    runner,
    '/usr/sbin/system_profiler',
    ['SPAirPortDataType', '-json'],
    signal,
  );
  const neighbors = await runCommandAsync(runner, '/usr/sbin/arp', ['-an'], signal);
  return {
    hardwarePorts,
    interfaces,
    interfaceStatusInventory,
    deviceInventory,
    airportMetadata,
    neighbors,
  };
}

/*** Report the observable L1 boundary while keeping physical controls explicitly manual and unknown. */
function physicalObservation(
  input: CollectorInput,
  sources: MacosPhysicalAndLinkSources,
): SecurityAuditObservation {
  return observation(
    'osi1-physical-interface-inventory',
    'unknown',
    sourceAccess(
      [sources.hardwarePorts, sources.interfaces, sources.deviceInventory],
      sources.interfaceStatusInventory,
    ),
    [
      evidence(
        input,
        'osi1-physical-interface-inventory',
        'physical-interface-sources',
        'Passive interface and device inventory was queried without identifiers.',
        [
          [
            'interface-source-available',
            sources.hardwarePorts.kind === 'available' || sources.interfaces.kind === 'available',
          ],
          ['external-device-source-available', sources.deviceInventory.kind === 'available'],
          ['manual-physical-controls-required', true],
          ...sourceFailureFacts(
            [sources.hardwarePorts, sources.interfaces, sources.deviceInventory],
            sources.interfaceStatusInventory,
          ),
        ],
      ),
    ],
  );
}

/*** Report the observable L2 boundary without inferring wireless or neighbor-cache security from metadata. */
function linkObservation(
  input: CollectorInput,
  sources: MacosPhysicalAndLinkSources,
): SecurityAuditObservation {
  return observation(
    'osi2-link-security',
    'unknown',
    sourceAccess(
      [sources.interfaces, sources.airportMetadata, sources.neighbors],
      sources.interfaceStatusInventory,
      hasParseFailure(sources.airportMetadata),
    ),
    [
      evidence(
        input,
        'osi2-link-security',
        'link-metadata-sources',
        'Passive link, bridge, VLAN, wireless, Bluetooth, and neighbor metadata was queried without identifiers.',
        [
          ['interface-metadata-source-available', sources.interfaces.kind === 'available'],
          [
            'link-status-source-available',
            sources.interfaceStatusInventory.results.some(isAvailable),
          ],
          [
            'wifi-security-metadata-publicly-observable',
            hasSecurityMetadata(sources.airportMetadata),
          ],
          ['bluetooth-metadata-source-available', sources.deviceInventory.kind === 'available'],
          ['neighbor-cache-source-available', sources.neighbors.kind === 'available'],
          ['manual-or-unknown-link-controls-remain', true],
          ...sourceFailureFacts(
            [sources.interfaces, sources.airportMetadata, sources.neighbors],
            sources.interfaceStatusInventory,
            hasParseFailure(sources.airportMetadata),
          ),
        ],
      ),
    ],
  );
}

/*** Return explicit non-applicability rather than running macOS binaries on another platform. */
function unsupportedPlatformObservations(
  input: CollectorInput,
): readonly SecurityAuditObservation[] {
  return ['osi1-physical-interface-inventory', 'osi2-link-security'].map((controlId) =>
    observation(controlId, 'not-applicable', 'available', [
      evidence(
        input,
        controlId,
        'platform',
        'macOS-only passive collector is not applicable on this platform.',
        [['macos-host', false]],
      ),
    ]),
  );
}

/*** Query link state only for kernel-reported interface names and retain no interface names in evidence. */
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

/*** Avoid starting another local command after the audit deadline has cancelled this collector. */
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

/*** Preserve source failure categories while exposing only redacted aggregate facts. */
function sourceFailureFacts(
  sources: readonly CommandResult[],
  interfaceStatuses: InterfaceStatusInventory,
  parseFailed = false,
): readonly (readonly [string, boolean])[] {
  const allSources = [...sources, ...interfaceStatuses.results];
  return [
    ['source-missing', allSources.some((source) => source.kind === 'missing')],
    ['source-permission-denied', allSources.some((source) => source.kind === 'permission-denied')],
    ['source-timed-out', allSources.some((source) => source.kind === 'timed-out')],
    ['source-failed', allSources.some((source) => source.kind === 'failed')],
    ['source-parse-failed', parseFailed || interfaceStatuses.parseFailed],
    ['interface-inventory-complete', !interfaceStatuses.truncated],
  ];
}

/*** Mark observations incomplete unless every requested source and bounded inventory completed. */
function sourceAccess(
  sources: readonly CommandResult[],
  interfaceStatuses: InterfaceStatusInventory,
  parseFailed = false,
): SecurityAuditObservation['access'] {
  const allSources = [...sources, ...interfaceStatuses.results];
  if (allSources.every((source) => source.kind === 'permission-denied'))
    return 'permission-blocked';
  if (
    allSources.every(isAvailable) &&
    !interfaceStatuses.truncated &&
    !interfaceStatuses.parseFailed &&
    !parseFailed
  )
    return 'available';
  return 'incomplete';
}

/*** Keep evidence deterministic, redacted, and compatible with the established audit-engine contract. */
function evidence(
  input: CollectorInput,
  controlId: string,
  id: string,
  summary: string,
  facts: readonly (readonly [string, boolean])[],
): SecurityAuditEvidence {
  return {
    id,
    controlId,
    profileId: input.profile.id,
    baselineVersion: input.profile.baseline,
    kind: 'macos-passive-command-summary',
    summary,
    collectedAt: input.collectedAt,
    redacted: true,
    facts: facts.map(([factId, value]) => ({ id: factId, value })),
  };
}

/*** Distinguish command availability without inferring that empty or unavailable output is a secure state. */
function isAvailable(result: CommandResult): boolean {
  return result.kind === 'available';
}

/*** Inspect only JSON key names so SSIDs, MAC addresses, device names, and pairing records never enter evidence. */
function hasSecurityMetadata(result: CommandResult): boolean {
  if (result.kind !== 'available') return false;
  try {
    return hasSecurityKey(JSON.parse(result.stdout));
  } catch {
    return false;
  }
}

/*** Detect malformed available JSON independently from a missing or inaccessible command. */
function hasParseFailure(result: CommandResult): boolean {
  if (result.kind !== 'available') return false;
  try {
    JSON.parse(result.stdout);
    return false;
  } catch {
    return true;
  }
}

/*** Find public metadata field names recursively while deliberately discarding every field value. */
function hasSecurityKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasSecurityKey);
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(
    ([key, nested]) =>
      /(?:security|authentication|encryption)/i.test(key) || hasSecurityKey(nested),
  );
}

/*** Preserve the engine's access and applicability vocabulary without collector-owned verdicts. */
function observation(
  controlId: string,
  applicability: SecurityAuditObservation['applicability'],
  access: SecurityAuditObservation['access'],
  evidenceItems: readonly SecurityAuditEvidence[],
): SecurityAuditObservation {
  return { controlId, applicability, access, evidence: evidenceItems };
}
