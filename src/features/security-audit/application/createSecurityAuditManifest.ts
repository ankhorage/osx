import type {
  SecurityAuditManifest,
  SecurityAuditProfile,
  SecurityAuditResult,
} from '../../../types/securityAudit.js';

/*** Create the deterministic, redacted control and evidence lineage inventory used by CI artifacts. */
export function createSecurityAuditManifest(
  profile: SecurityAuditProfile,
  results: readonly SecurityAuditResult[],
): SecurityAuditManifest {
  return {
    schemaVersion: 1,
    profileId: profile.id,
    profileVersion: profile.version,
    baseline: profile.baseline,
    controls: [...results]
      .sort((left, right) => left.control.id.localeCompare(right.control.id))
      .map((result) => createManifestControl(result)),
  };
}

/** Create one control record, retaining only stable IDs and engine-owned outcomes. */
function createManifestControl(
  result: SecurityAuditResult,
): SecurityAuditManifest['controls'][number] {
  const evidenceIds = result.evidence.map((evidence) => evidence.id).sort();
  const evidenceBySource = new Map(
    result.evidence.map((evidence) => [
      evidence.sourceId ?? `evidence:${evidence.id}`,
      evidence.id,
    ]),
  );
  const sources = sourceIdsFor(result.control.id).map((id) => {
    const evidenceId = evidenceBySource.get(id);
    return {
      id,
      state: evidenceId === undefined ? sourceStateFor(result) : ('completed' as const),
      evidenceIds: evidenceId === undefined ? [] : [evidenceId],
    };
  });
  return {
    controlId: result.control.id,
    category:
      result.control.primaryCategory.kind === 'osi'
        ? `osi-${result.control.primaryCategory.layer}`
        : result.control.primaryCategory.theme,
    coverage: result.coverage,
    outcome: result.outcome,
    baselineStatus: result.baseline.status,
    evidenceIds,
    sources,
  };
}

/** Map only engine-owned absence states to conservative source states. */
function sourceStateFor(
  result: SecurityAuditResult,
): SecurityAuditManifest['controls'][number]['sources'][number]['state'] {
  if (result.coverage === 'unsupported') return 'unsupported';
  if (result.coverage === 'permission-blocked') return 'permission-blocked';
  if (result.coverage === 'incomplete' || result.baseline.status === 'incomplete-evidence')
    return 'unclassified';
  if (result.control.detectionMode === 'manual') return 'manual';
  return 'not-queried';
}

/** Keep the known, non-sensitive source inventory beside the report transformation. */
function sourceIdsFor(controlId: string): readonly string[] {
  return sourceIds.get(controlId) ?? [`manual:${controlId}`];
}

const sourceIds = new Map<string, readonly string[]>([
  ['osi1-physical-interface-inventory', ['macos-passive:physical-interface-sources']],
  ['osi2-link-security', ['macos-passive:link-metadata-sources']],
  ['osi3-routing-and-filtering', ['macos-network:osi3-routing-and-filtering']],
  ['osi4-service-exposure', ['macos-network:osi4-service-exposure']],
  ['osi5-remote-session-services', ['macos-posture:osi5-remote-session-services']],
  ['osi6-presentation-trust', ['macos-posture:osi6-presentation-trust']],
  [
    'osi7-application-network-and-persistence',
    ['macos-posture:osi7-application-network-and-persistence'],
  ],
  ['cross-layer-hardware-startup-trust', ['csrutil-status', 'csrutil-authenticated-root-status']],
  ['cross-layer-disk-data', ['fdesetup-status']],
  ['cross-layer-identity-access', ['sysadminctl-guest-account-status']],
  ['cross-layer-malware-integrity', ['spctl-status']],
  ['cross-layer-backups-resilience-logging', ['tmutil-destinationinfo']],
  ['cross-layer-enterprise-policy', ['profiles-enrollment-status']],
]);
