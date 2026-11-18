import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../../types/securityAudit.js';

type CommandResult =
  { readonly kind: 'available'; readonly stdout: string } | { readonly kind: 'unavailable' };

export interface MacosSecurityAuditCommandRunner {
  readonly platform: string;
  run(command: string, arguments_: readonly string[]): CommandResult;
}

interface CollectorInput {
  readonly runner: MacosSecurityAuditCommandRunner;
  readonly profile: SecurityAuditProfile;
  readonly collectedAt: string;
}

/*** Collect redacted, passive OSI 1 and 2 observations without exposing host identifiers or mutating macOS. */
export function collectMacosPhysicalAndLinkObservations(
  input: CollectorInput,
): readonly SecurityAuditObservation[] {
  if (input.runner.platform !== 'darwin') return unsupportedPlatformObservations(input);
  const sources = collectSources(input.runner);
  return [physicalObservation(input, sources), linkObservation(input, sources)];
}

interface MacosPhysicalAndLinkSources {
  readonly hardwarePorts: CommandResult;
  readonly interfaces: CommandResult;
  readonly interfaceStatuses: readonly CommandResult[];
  readonly deviceInventory: CommandResult;
  readonly airportMetadata: CommandResult;
  readonly neighbors: CommandResult;
}

/** Query only public, local macOS inspection commands through the injected outer boundary. */
function collectSources(runner: MacosSecurityAuditCommandRunner): MacosPhysicalAndLinkSources {
  const hardwarePorts = runner.run('/usr/sbin/networksetup', ['-listallhardwareports']);
  const interfaces = runner.run('/sbin/ifconfig', ['-l']);
  const interfaceStatuses = interfaceStatusResults(runner, interfaces);
  const deviceInventory = runner.run('/usr/sbin/system_profiler', [
    'SPUSBDataType',
    'SPThunderboltDataType',
    'SPBluetoothDataType',
    '-json',
  ]);
  const airportMetadata = runner.run('/usr/sbin/system_profiler', ['SPAirPortDataType', '-json']);
  const neighbors = runner.run('/usr/sbin/arp', ['-an']);
  return {
    hardwarePorts,
    interfaces,
    interfaceStatuses,
    deviceInventory,
    airportMetadata,
    neighbors,
  };
}

/** Report the observable L1 boundary while keeping physical controls explicitly manual and unknown. */
function physicalObservation(
  input: CollectorInput,
  sources: MacosPhysicalAndLinkSources,
): SecurityAuditObservation {
  const physicalAvailable =
    sources.hardwarePorts.kind === 'available' ||
    sources.interfaces.kind === 'available' ||
    sources.deviceInventory.kind === 'available';
  return observation(
    'osi1-physical-interface-inventory',
    'unknown',
    physicalAvailable ? 'available' : 'permission-blocked',
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
        ],
      ),
    ],
  );
}

/** Report the observable L2 boundary without inferring wireless or neighbor-cache security from metadata. */
function linkObservation(
  input: CollectorInput,
  sources: MacosPhysicalAndLinkSources,
): SecurityAuditObservation {
  const linkAvailable =
    sources.interfaces.kind === 'available' ||
    sources.airportMetadata.kind === 'available' ||
    sources.neighbors.kind === 'available';
  return observation(
    'osi2-link-security',
    'unknown',
    linkAvailable ? 'available' : 'permission-blocked',
    [
      evidence(
        input,
        'osi2-link-security',
        'link-metadata-sources',
        'Passive link, bridge, VLAN, wireless, Bluetooth, and neighbor metadata was queried without identifiers.',
        [
          ['interface-metadata-source-available', sources.interfaces.kind === 'available'],
          ['link-status-source-available', sources.interfaceStatuses.some(isAvailable)],
          [
            'wifi-security-metadata-publicly-observable',
            hasSecurityMetadata(sources.airportMetadata),
          ],
          ['bluetooth-metadata-source-available', sources.deviceInventory.kind === 'available'],
          ['neighbor-cache-source-available', sources.neighbors.kind === 'available'],
          ['manual-or-unknown-link-controls-remain', true],
        ],
      ),
    ],
  );
}

/** Return explicit non-applicability rather than running macOS binaries on another platform. */
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

/** Query link state only for kernel-reported interface names and retain no interface names in evidence. */
function interfaceStatusResults(
  runner: MacosSecurityAuditCommandRunner,
  interfaces: CommandResult,
): readonly CommandResult[] {
  if (interfaces.kind === 'unavailable') return [];
  return interfaces.stdout
    .trim()
    .split(/\s+/)
    .filter((name) => /^[a-z]+\d+$/.test(name))
    .sort()
    .map((name) => runner.run('/sbin/ifconfig', [name]));
}

/** Keep evidence deterministic, redacted, and compatible with the established audit-engine contract. */
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

/** Distinguish command availability without inferring that empty or unavailable output is a secure state. */
function isAvailable(result: CommandResult): boolean {
  return result.kind === 'available';
}

/** Inspect only JSON key names so SSIDs, MAC addresses, device names, and pairing records never enter evidence. */
function hasSecurityMetadata(result: CommandResult): boolean {
  if (result.kind === 'unavailable') return false;
  try {
    return hasSecurityKey(JSON.parse(result.stdout));
  } catch {
    return false;
  }
}

/** Find public metadata field names recursively while deliberately discarding every field value. */
function hasSecurityKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasSecurityKey);
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(
    ([key, nested]) =>
      /(?:security|authentication|encryption)/i.test(key) || hasSecurityKey(nested),
  );
}

/** Preserve the engine's access and applicability vocabulary without collector-owned verdicts. */
function observation(
  controlId: string,
  applicability: SecurityAuditObservation['applicability'],
  access: SecurityAuditObservation['access'],
  evidenceItems: readonly SecurityAuditEvidence[],
): SecurityAuditObservation {
  return { controlId, applicability, access, evidence: evidenceItems };
}
