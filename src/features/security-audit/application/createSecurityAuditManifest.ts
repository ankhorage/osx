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
    sources: result.sources,
  };
}
