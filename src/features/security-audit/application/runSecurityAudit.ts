import type {
  SecurityAuditControl,
  SecurityAuditCoverage,
  SecurityAuditCoverageMatrix,
  SecurityAuditCoverageTotals,
  SecurityAuditObservation,
  SecurityAuditProfile,
  SecurityAuditReport,
  SecurityAuditResult,
} from '../../../types/securityAudit.js';

/*** Evaluate injected read-only observations without upgrading missing evidence to a passing result. */
export function runSecurityAudit(
  controls: readonly SecurityAuditControl[],
  profile: SecurityAuditProfile,
  observations: readonly SecurityAuditObservation[],
): SecurityAuditReport {
  const observationsByControlId = new Map(
    observations.map((observation) => [observation.controlId, observation]),
  );
  if (observationsByControlId.size !== observations.length)
    throw new Error('Duplicate audit observations are ambiguous.');
  const controlsById = new Set(controls.map((control) => control.id));
  if (controlsById.size !== controls.length)
    throw new Error('Duplicate audit control identifiers are ambiguous.');
  for (const observation of observations)
    if (!controlsById.has(observation.controlId))
      throw new Error(`Unknown audit control: ${observation.controlId}`);
  const results = controls
    .map((control) => createResult(control, observationsByControlId.get(control.id)))
    .sort((left, right) => left.control.id.localeCompare(right.control.id));
  return { schemaVersion: 1, profile, results, coverage: createCoverageMatrix(results) };
}

/** Convert an absent collector result into an explicit, non-passing coverage state. */
function createResult(
  control: SecurityAuditControl,
  observation: SecurityAuditObservation | undefined,
): SecurityAuditResult {
  if (!observation) {
    return {
      control,
      applicability: 'unknown',
      coverage: 'unsupported',
      outcome: 'unknown',
      severity: 'info',
      confidence: 'none',
      evidence: [],
      recommendation: control.recommendation,
    };
  }
  return {
    control,
    applicability: observation.applicability,
    coverage: observation.coverage,
    outcome: observation.outcome,
    severity: observation.severity,
    confidence: observation.confidence,
    evidence: [...observation.evidence].sort((left, right) => left.id.localeCompare(right.id)),
    recommendation: observation.recommendation ?? control.recommendation,
  };
}

/** Count primary-category coverage only, so cross references cannot inflate completeness. */
function createCoverageMatrix(
  results: readonly SecurityAuditResult[],
): SecurityAuditCoverageMatrix {
  const osi = Object.fromEntries(
    [1, 2, 3, 4, 5, 6, 7].map((layer) => [layer, emptyTotals()]),
  ) as Record<1 | 2 | 3 | 4 | 5 | 6 | 7, SecurityAuditCoverageTotals>;
  const themes = [
    'hardware-startup-trust',
    'disk-data',
    'identity-access',
    'privacy-permissions',
    'malware-integrity',
    'patching-exposure',
    'network-trust',
    'development-supply-chain',
    'backups-resilience-logging',
    'enterprise-policy',
  ] as const;
  const crossLayer = Object.fromEntries(themes.map((theme) => [theme, emptyTotals()])) as Record<
    (typeof themes)[number],
    SecurityAuditCoverageTotals
  >;
  for (const result of results) {
    const category = result.control.primaryCategory;
    if (category.kind === 'osi')
      osi[category.layer] = addCoverage(osi[category.layer], result.coverage);
    else crossLayer[category.theme] = addCoverage(crossLayer[category.theme], result.coverage);
  }
  return { osi, crossLayer };
}

/** Create an empty immutable-shaped coverage counter. */
function emptyTotals(): SecurityAuditCoverageTotals {
  return { implemented: 0, supported: 0, unsupported: 0, permissionBlocked: 0 };
}

/** Increment the one coverage state represented by a control result. */
function addCoverage(
  totals: SecurityAuditCoverageTotals,
  coverage: SecurityAuditCoverage,
): SecurityAuditCoverageTotals {
  if (coverage === 'implemented') return { ...totals, implemented: totals.implemented + 1 };
  if (coverage === 'supported') return { ...totals, supported: totals.supported + 1 };
  if (coverage === 'permission-blocked')
    return { ...totals, permissionBlocked: totals.permissionBlocked + 1 };
  return { ...totals, unsupported: totals.unsupported + 1 };
}
