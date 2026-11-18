import type {
  SecurityAuditBaseline,
  SecurityAuditBaselineEvaluation,
  SecurityAuditControl,
  SecurityAuditCoverage,
  SecurityAuditCoverageMatrix,
  SecurityAuditCoverageTotals,
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
  SecurityAuditReport,
  SecurityAuditResult,
} from '../../../types/securityAudit.js';

/*** Evaluate read-only observations from their validated evidence and the selected control baseline. */
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
  if (controls.some((control) => !isNonEmpty(control.id)))
    throw new Error('Invalid audit control identifier.');
  for (const observation of observations)
    if (!controlsById.has(observation.controlId))
      throw new Error(`Unknown audit control: ${observation.controlId}`);
  const profileIsValid = isValidProfile(profile);
  const results = controls
    .map((control) =>
      createResult(control, profile, observationsByControlId.get(control.id), profileIsValid),
    )
    .sort((left, right) => left.control.id.localeCompare(right.control.id));
  return { schemaVersion: 1, profile, results, coverage: createCoverageMatrix(results) };
}

/** Create one result without trusting collector-supplied outcome, severity, coverage, or confidence. */
function createResult(
  control: SecurityAuditControl,
  profile: SecurityAuditProfile,
  observation: SecurityAuditObservation | undefined,
  profileIsValid: boolean,
): SecurityAuditResult {
  const baseline = control.baselines.find((candidate) => candidate.profileId === profile.id);
  if (!profileIsValid || !baseline || !isValidBaseline(baseline))
    return createUnknownResult(control, 'unsupported', 'profile-incompatible');
  if (!observation)
    return createUnknownResult(control, 'unsupported', 'missing-evidence', baseline);
  if (observation.access === 'permission-blocked')
    return createUnknownResult(control, 'permission-blocked', 'inaccessible-evidence', baseline);
  if (!hasMetadataValue(observation, 'access', 'available'))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  if (!hasValidApplicability(observation))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  const evidence = [...observation.evidence].sort((left, right) => left.id.localeCompare(right.id));
  if (evidence.length === 0)
    return createUnknownResult(control, 'supported', 'missing-evidence', baseline);
  if (!hasValidEvidence(evidence, control, profile, baseline))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  if (observation.applicability === 'unknown')
    return createUnknownResult(control, 'implemented', 'applicability-unknown', baseline, evidence);
  if (observation.applicability === 'not-applicable')
    return createNotApplicableResult(control, baseline, evidence);
  const baselineStatuses = new Set(evidence.map((item) => item.baselineStatus));
  if (baselineStatuses.size !== 1)
    return createUnknownResult(
      control,
      'implemented',
      'contradictory-evidence',
      baseline,
      evidence,
    );
  if (baselineStatuses.has('violated')) return createFailedResult(control, baseline, evidence);
  return createPassedResult(control, baseline, evidence);
}

/** Validate that the active profile names a versioned, internally consistent baseline. */
function isValidProfile(profile: SecurityAuditProfile): boolean {
  return (
    isNonEmpty(profile.id) &&
    isNonEmpty(profile.version) &&
    isNonEmpty(profile.title) &&
    isNonEmpty(profile.description) &&
    profile.baseline.endsWith(`-v${profile.version}`)
  );
}

/** Validate that control-owned policy contains a usable condition and a defined failure severity. */
function isValidBaseline(baseline: SecurityAuditBaseline): boolean {
  return (
    isNonEmpty(baseline.profileId) &&
    isNonEmpty(baseline.expectedSecureCondition) &&
    (hasMetadataValue(baseline, 'failureSeverity', 'info') ||
      hasMetadataValue(baseline, 'failureSeverity', 'low') ||
      hasMetadataValue(baseline, 'failureSeverity', 'medium') ||
      hasMetadataValue(baseline, 'failureSeverity', 'high') ||
      hasMetadataValue(baseline, 'failureSeverity', 'critical'))
  );
}

/** Validate collector applicability at the untyped adapter boundary. */
function hasValidApplicability(observation: SecurityAuditObservation): boolean {
  return (
    hasMetadataValue(observation, 'applicability', 'applicable') ||
    hasMetadataValue(observation, 'applicability', 'not-applicable') ||
    hasMetadataValue(observation, 'applicability', 'unknown')
  );
}

/** Reject incomplete, misattributed, unredacted, stale-format, or potentially sensitive evidence. */
function hasValidEvidence(
  evidence: readonly SecurityAuditEvidence[],
  control: SecurityAuditControl,
  profile: SecurityAuditProfile,
  baseline: SecurityAuditBaseline,
): boolean {
  const evidenceIds = new Set(evidence.map((item) => item.id));
  const evidenceIsValid = evidence.every(
    (item) =>
      isNonEmpty(item.id) &&
      isNonEmpty(item.kind) &&
      isNonEmpty(item.summary) &&
      item.controlId === control.id &&
      item.profileId === profile.id &&
      item.baselineVersion === profile.baseline &&
      hasMetadataValue(item, 'redacted', true) &&
      (hasMetadataValue(item, 'baselineStatus', 'satisfied') ||
        hasMetadataValue(item, 'baselineStatus', 'violated')) &&
      isTimestamp(item.collectedAt) &&
      !containsSensitiveContent(item.summary) &&
      baseline.expectedSecureCondition.length > 0,
  );
  return evidenceIds.size === evidence.length && evidenceIsValid;
}

/** Read untrusted runtime metadata without relying on TypeScript's compile-time literal narrowing. */
function hasMetadataValue(
  value: object,
  key: 'access' | 'applicability' | 'baselineStatus' | 'failureSeverity' | 'redacted',
  expected:
    | 'applicable'
    | 'available'
    | 'critical'
    | 'high'
    | 'info'
    | 'low'
    | 'medium'
    | 'not-applicable'
    | 'satisfied'
    | 'unknown'
    | 'violated'
    | true,
): boolean {
  return Object.getOwnPropertyDescriptor(value, key)?.value === expected;
}

/** Check a serializable metadata field without accepting whitespace-only values. */
function isNonEmpty(value: string): boolean {
  return value.trim().length > 0;
}

/** Accept only unambiguous ISO timestamps so reports remain machine-readable and comparable. */
function isTimestamp(value: string): boolean {
  return (
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && !Number.isNaN(Date.parse(value))
  );
}

/** Block common secret, identifier, address, and personal-path forms from a supposedly redacted summary. */
function containsSensitiveContent(summary: string): boolean {
  return /-----BEGIN|\b(password|passwd|secret|token|private[ _-]?key|keychain|ssid)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\/Users\//i.test(
    summary,
  );
}

/** Produce a result that cannot accidentally be read as a successful security evaluation. */
function createUnknownResult(
  control: SecurityAuditControl,
  coverage: SecurityAuditCoverage,
  status: Exclude<SecurityAuditBaselineEvaluation['status'], 'verified'>,
  baseline?: SecurityAuditBaseline,
  evidence: readonly SecurityAuditEvidence[] = [],
): SecurityAuditResult {
  return {
    control,
    applicability: 'unknown',
    coverage,
    outcome: 'unknown',
    severity: 'info',
    confidence: 'none',
    evidence,
    recommendation: control.recommendation,
    baseline: createBaselineEvaluation(baseline, status, evidence),
  };
}

/** Produce an evidence-backed non-applicable result without treating it as a security pass. */
function createNotApplicableResult(
  control: SecurityAuditControl,
  baseline: SecurityAuditBaseline,
  evidence: readonly SecurityAuditEvidence[],
): SecurityAuditResult {
  return {
    control,
    applicability: 'not-applicable',
    coverage: 'implemented',
    outcome: 'not-applicable',
    severity: 'info',
    confidence: confidenceFor(evidence),
    evidence,
    recommendation: control.recommendation,
    baseline: createBaselineEvaluation(baseline, 'verified', evidence),
  };
}

/** Produce the only path that may return pass: coherent valid evidence satisfies the active baseline. */
function createPassedResult(
  control: SecurityAuditControl,
  baseline: SecurityAuditBaseline,
  evidence: readonly SecurityAuditEvidence[],
): SecurityAuditResult {
  return {
    control,
    applicability: 'applicable',
    coverage: 'implemented',
    outcome: 'pass',
    severity: 'info',
    confidence: confidenceFor(evidence),
    evidence,
    recommendation: control.recommendation,
    baseline: createBaselineEvaluation(baseline, 'verified', evidence),
  };
}

/** Derive failure severity from the selected control definition rather than a collector assertion. */
function createFailedResult(
  control: SecurityAuditControl,
  baseline: SecurityAuditBaseline,
  evidence: readonly SecurityAuditEvidence[],
): SecurityAuditResult {
  return {
    control,
    applicability: 'applicable',
    coverage: 'implemented',
    outcome: 'fail',
    severity: baseline.failureSeverity,
    confidence: confidenceFor(evidence),
    evidence,
    recommendation: control.recommendation,
    baseline: createBaselineEvaluation(baseline, 'verified', evidence),
  };
}

/** Preserve the selected baseline and its exact evidence identifiers in every report result. */
function createBaselineEvaluation(
  baseline: SecurityAuditBaseline | undefined,
  status: SecurityAuditBaselineEvaluation['status'],
  evidence: readonly SecurityAuditEvidence[],
): SecurityAuditBaselineEvaluation {
  return {
    profileId: baseline?.profileId ?? '',
    expectedSecureCondition: baseline?.expectedSecureCondition ?? '',
    status,
    evidenceIds: evidence.map((item) => item.id),
  };
}

/** Use evidence quantity only for a conservative, engine-owned confidence level. */
function confidenceFor(evidence: readonly SecurityAuditEvidence[]): 'low' | 'medium' {
  return evidence.length === 1 ? 'low' : 'medium';
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
