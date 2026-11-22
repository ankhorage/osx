import type {
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
  SecurityAuditSourceProvenance,
} from '../../../../types/securityAudit.js';
import {
  collectMacosPhysicalAndLinkSourcesAsync,
  type InterfaceStatusInventory,
  type LinkSources,
  type PhysicalSources,
} from './collectMacosPhysicalAndLinkSourcesAsync.js';
import type {
  MacosSecurityAuditCommandResult as CommandResult,
  MacosSecurityAuditCommandRunner,
} from './createMacosSecurityAuditCommandRunner.js';

interface CollectorInput {
  readonly runner: MacosSecurityAuditCommandRunner;
  readonly profile: SecurityAuditProfile;
  readonly collectedAt: string;
  readonly controlIds?: ReadonlySet<string>;
  readonly signal?: AbortSignal;
}

/*** Collect redacted, passive OSI 1 and 2 observations without exposing host identifiers or mutating macOS. */
export async function collectMacosPhysicalAndLinkObservationsAsync(
  input: CollectorInput,
): Promise<readonly SecurityAuditObservation[]> {
  if (input.runner.platform !== 'darwin') return unsupportedPlatformObservations(input);
  const physical = includesControl(input, 'osi1-physical-interface-inventory');
  const link = includesControl(input, 'osi2-link-security');
  if (!physical && !link) return [];
  const sources = await collectMacosPhysicalAndLinkSourcesAsync(
    input.runner,
    physical,
    link,
    input.signal,
  );
  return [
    ...(sources.physical ? [physicalObservation(input, sources.physical)] : []),
    ...(sources.link ? [linkObservation(input, sources.link)] : []),
  ];
}

/*** Report the observable L1 boundary while keeping physical controls explicitly manual and unknown. */
function physicalObservation(
  input: CollectorInput,
  sources: PhysicalSources,
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
    sourceProvenance([
      ['macos-passive:hardware-ports', sources.hardwarePorts],
      ['macos-passive:interfaces', sources.interfaces],
      ['macos-passive:device-inventory', sources.deviceInventory],
      ...interfaceStatusSources(sources.interfaceStatusInventory),
    ]),
  );
}

/*** Report the observable L2 boundary without inferring wireless or neighbor-cache security from metadata. */
function linkObservation(input: CollectorInput, sources: LinkSources): SecurityAuditObservation {
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
    sourceProvenance([
      ['macos-passive:interfaces', sources.interfaces],
      ['macos-passive:device-inventory', sources.deviceInventory],
      ['macos-passive:airport-metadata', sources.airportMetadata],
      ['macos-passive:neighbors', sources.neighbors],
      ...interfaceStatusSources(sources.interfaceStatusInventory),
    ]),
  );
}

/*** Return explicit non-applicability rather than running macOS binaries on another platform. */
function unsupportedPlatformObservations(
  input: CollectorInput,
): readonly SecurityAuditObservation[] {
  return ['osi1-physical-interface-inventory', 'osi2-link-security']
    .filter((controlId) => includesControl(input, controlId))
    .map((controlId) =>
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

/** Treat an omitted scope as the public collector's complete L1/L2 request. */
function includesControl(input: CollectorInput, controlId: string): boolean {
  return input.controlIds?.has(controlId) ?? true;
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
    sourceId: `macos-passive:${id}`,
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
  sourceStates: readonly SecurityAuditSourceProvenance[] = [],
): SecurityAuditObservation {
  return {
    controlId,
    applicability,
    access,
    evidence: evidenceItems,
    sources: [
      ...sourceStates,
      ...evidenceItems.map((item) => ({
        id: item.sourceId ?? 'macos-passive:physical-interface-sources',
        state: 'completed' as const,
        evidenceIds: [item.id],
      })),
    ],
  };
}

/** Translate each fixed passive command attempt into a registered redacted source outcome. */
function sourceProvenance(
  sources: readonly (readonly [string, CommandResult])[],
): readonly SecurityAuditSourceProvenance[] {
  return sources.map(([id, result]) => ({ id, state: sourceState(result), evidenceIds: [] }));
}

/** Preserve the bounded probe ordinal without exposing the host interface name that was queried. */
function interfaceStatusSources(
  inventory: InterfaceStatusInventory,
): readonly (readonly [string, CommandResult])[] {
  return inventory.results.map((result, index) => [
    `macos-passive:interface-status-${index + 1}`,
    result,
  ]);
}

/** Map the command adapter's explicit outcome without upgrading failures to a security conclusion. */
function sourceState(result: CommandResult): SecurityAuditSourceProvenance['state'] {
  if (result.kind === 'available') return 'completed';
  if (result.kind === 'missing') return 'missing';
  if (result.kind === 'permission-denied') return 'permission-blocked';
  if (result.kind === 'timed-out') return 'timed-out';
  return 'failed';
}
