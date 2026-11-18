import type {
  SecurityAuditBaseline,
  SecurityAuditBaselineEvaluation,
  SecurityAuditControl,
  SecurityAuditCoverage,
  SecurityAuditEvidence,
  SecurityAuditObservation,
  SecurityAuditProfile,
  SecurityAuditReport,
  SecurityAuditResult,
} from '../../../types/securityAudit.js';
import { createSecurityAuditCoverageMatrix } from '../domain/createSecurityAuditCoverageMatrix.js';
import { validateSecurityAuditFacts } from '../domain/validateSecurityAuditFacts.js';
import { createSecurityAuditBaselineEvaluation } from './createSecurityAuditBaselineEvaluation.js';
import { getSecurityAuditAccessResult } from './getSecurityAuditAccessResult.js';
/*** Evaluate read-only observations from their validated evidence and the selected control baseline. */
export function runSecurityAudit(
  controls: readonly SecurityAuditControl[],
  profile: SecurityAuditProfile,
  observations: readonly SecurityAuditObservation[],
): SecurityAuditReport {
  const controlsById = new Set(controls.map((control) => control.id));
  if (controlsById.size !== controls.length)
    throw new Error('Duplicate audit control identifiers are ambiguous.');
  if (controls.some((control) => !isNonEmpty(control.id)))
    throw new Error('Invalid audit control identifier.');
  const observationsByControlId = collectObservationsByControlId(controlsById, observations);
  const profileIsValid = isValidProfile(profile);
  const results = controls
    .map((control) =>
      createResult(control, profile, observationsByControlId.get(control.id), profileIsValid),
    )
    .sort((left, right) => left.control.id.localeCompare(right.control.id));
  return {
    schemaVersion: 1,
    profile,
    results,
    coverage: createSecurityAuditCoverageMatrix(results),
  };
}

/** Create one result without trusting collector-supplied outcome, severity, coverage, or confidence. */
function createResult(
  control: SecurityAuditControl,
  profile: SecurityAuditProfile,
  observation: unknown,
  profileIsValid: boolean,
): SecurityAuditResult {
  const baseline = control.baselines.find((candidate) => candidate.profileId === profile.id);
  if (!profileIsValid || !baseline || !isValidBaseline(baseline))
    return createUnknownResult(control, 'unsupported', 'profile-incompatible');
  if (observation === undefined)
    return createUnknownResult(control, 'unsupported', 'missing-evidence', baseline);
  if (!isRecord(observation))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  const inaccessibleAccess = getSecurityAuditAccessResult(observation);
  if (inaccessibleAccess)
    return createUnknownResult(control, inaccessibleAccess[0], inaccessibleAccess[1], baseline);
  if (!hasMetadataValue(observation, 'access', 'available'))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  if (!hasValidApplicability(observation))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  if (!Array.isArray(observation.evidence))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  const evidence = sortEvidence(observation.evidence);
  if (!evidence) return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  if (evidence.length === 0)
    return createUnknownResult(control, 'supported', 'missing-evidence', baseline);
  if (!hasValidEvidence(evidence, control, profile, baseline))
    return createUnknownResult(control, 'supported', 'invalid-evidence', baseline);
  if (observation.applicability === 'unknown')
    return createUnknownResult(control, 'implemented', 'applicability-unknown', baseline, evidence);
  if (observation.applicability === 'not-applicable')
    return createNotApplicableResult(control, baseline, evidence);
  return createPredicateResult(control, baseline, evidence);
}
/** Group untrusted collector records without allowing malformed or duplicate JSON to abort the report. */
function collectObservationsByControlId(
  controlsById: ReadonlySet<string>,
  observations: unknown,
): ReadonlyMap<string, unknown> {
  if (!Array.isArray(observations)) return new Map();
  return observations.reduce<ReadonlyMap<string, unknown>>((collected, observation) => {
    if (
      !isRecord(observation) ||
      !isNonEmpty(observation.controlId) ||
      !controlsById.has(observation.controlId)
    )
      return collected;
    if (collected.has(observation.controlId))
      return new Map([...collected, [observation.controlId, null]]);
    return new Map([...collected, [observation.controlId, observation]]);
  }, new Map());
}
/** Sort only validated evidence so malformed JSON is never echoed into a report. */
function sortEvidence(value: readonly unknown[]): readonly SecurityAuditEvidence[] | undefined {
  if (!value.every(isRecord)) return undefined;
  if (!value.every((item) => typeof item.id === 'string')) return undefined;
  return [...(value as unknown as readonly SecurityAuditEvidence[])].sort((left, right) =>
    left.id.localeCompare(right.id),
  );
}
/** Validate that the active profile names a versioned, internally consistent baseline. */
function isValidProfile(profile: SecurityAuditProfile): boolean {
  return (
    isRecord(profile) &&
    isNonEmpty(profile.id) &&
    isNonEmpty(profile.version) &&
    isNonEmpty(profile.title) &&
    isNonEmpty(profile.description) &&
    isNonEmpty(profile.baseline) &&
    profile.baseline.endsWith(`-v${profile.version}`)
  );
}

/** Validate that control-owned policy contains a usable condition and a defined failure severity. */
function isValidBaseline(baseline: SecurityAuditBaseline): boolean {
  return (
    isNonEmpty(baseline.profileId) &&
    isNonEmpty(baseline.expectedSecureCondition) &&
    validateSecurityAuditFacts(undefined, baseline.predicate) &&
    (hasMetadataValue(baseline, 'failureSeverity', 'info') ||
      hasMetadataValue(baseline, 'failureSeverity', 'low') ||
      hasMetadataValue(baseline, 'failureSeverity', 'medium') ||
      hasMetadataValue(baseline, 'failureSeverity', 'high') ||
      hasMetadataValue(baseline, 'failureSeverity', 'critical'))
  );
}

/** Validate collector applicability at the untyped adapter boundary. */
function hasValidApplicability(observation: object): boolean {
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
      isRecord(item) &&
      isNonEmpty(item.id) &&
      isNonEmpty(item.kind) &&
      isNonEmpty(item.summary) &&
      item.controlId === control.id &&
      item.profileId === profile.id &&
      item.baselineVersion === profile.baseline &&
      hasMetadataValue(item, 'redacted', true) &&
      validateSecurityAuditFacts(item.facts, baseline.predicate) &&
      isTimestamp(item.collectedAt) &&
      !containsSensitiveContent(item.summary),
  );
  return evidenceIds.size === evidence.length && evidenceIsValid;
}

/** Read untrusted runtime metadata without relying on TypeScript's compile-time literal narrowing. */
function hasMetadataValue(
  value: object,
  key: 'access' | 'applicability' | 'failureSeverity' | 'redacted',
  expected:
    | 'applicable'
    | 'available'
    | 'critical'
    | 'high'
    | 'info'
    | 'incomplete'
    | 'low'
    | 'medium'
    | 'not-applicable'
    | 'permission-blocked'
    | 'unknown'
    | true,
): boolean {
  return Object.getOwnPropertyDescriptor(value, key)?.value === expected;
}

/** Check a serializable metadata field without accepting whitespace-only values. */
function isNonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/** Accept only unambiguous ISO timestamps so reports remain machine-readable and comparable. */
function isTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value))
  );
}

/** Block common secret, identifier, address, and personal-path forms from a supposedly redacted summary. */
function containsSensitiveContent(summary: unknown): boolean {
  return (
    typeof summary !== 'string' ||
    /-----BEGIN|\b(password|passwd|secret|token|private[ _-]?key|keychain|ssid)\b|\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b|\/Users\//i.test(
      summary,
    )
  );
}

/** Evaluate typed source facts against the control-owned predicate without collector status claims. */
function createPredicateResult(
  control: SecurityAuditControl,
  baseline: SecurityAuditBaseline,
  evidence: readonly SecurityAuditEvidence[],
): SecurityAuditResult {
  const facts = evidence.flatMap((item) => item.facts);
  const valuesById = new Map<string, boolean[]>();
  for (const fact of facts)
    valuesById.set(fact.id, [...(valuesById.get(fact.id) ?? []), fact.value]);
  const expectedFacts = baseline.predicate.facts;
  if (expectedFacts.some((fact) => !valuesById.has(fact.id)))
    return createUnknownResult(control, 'implemented', 'missing-evidence', baseline, evidence);
  if (
    expectedFacts.some((fact) => {
      const values = valuesById.get(fact.id) ?? [];
      return new Set(values).size !== 1;
    })
  )
    return createUnknownResult(
      control,
      'implemented',
      'contradictory-evidence',
      baseline,
      evidence,
    );
  if (expectedFacts.some((fact) => (valuesById.get(fact.id) ?? [])[0] !== fact.value))
    return createFailedResult(control, baseline, evidence);
  return createPassedResult(control, baseline, evidence);
}

/** Narrow externally supplied JSON before reading its fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
    baseline: createSecurityAuditBaselineEvaluation(baseline, status, evidence),
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
    baseline: createSecurityAuditBaselineEvaluation(baseline, 'verified', evidence),
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
    baseline: createSecurityAuditBaselineEvaluation(baseline, 'verified', evidence),
  };
}

/** Derive failure severity from the selected control definition rather than a collector assertion. */ function createFailedResult(
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
    baseline: createSecurityAuditBaselineEvaluation(baseline, 'verified', evidence),
  };
}

/** Use evidence quantity only for a conservative, engine-owned confidence level. */
function confidenceFor(evidence: readonly SecurityAuditEvidence[]): 'low' | 'medium' {
  return evidence.length === 1 ? 'low' : 'medium';
}
