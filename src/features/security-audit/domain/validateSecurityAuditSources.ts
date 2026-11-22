import type {
  SecurityAuditEvidence,
  SecurityAuditSourceProvenance,
} from '../../../types/securityAudit.js';
import { isSecurityAuditSourceId } from './securityAuditSourceRegistry.js';

/*** Validate safe, complete evidence-to-source provenance supplied by a collector adapter. */
export function validateSecurityAuditSources(
  observation: unknown,
  evidence: readonly SecurityAuditEvidence[],
): readonly SecurityAuditSourceProvenance[] | undefined {
  if (observation === undefined) return [];
  if (!isRecord(observation)) return undefined;
  const lineageEvidence = evidenceForLineage(observation, evidence);
  const sources = observationSources(observation.sources, lineageEvidence);
  if (sources === undefined) return undefined;
  const evidenceIds = new Set(lineageEvidence.map((item) => item.id));
  const sourceIds = new Set<string>();
  const linkedEvidenceIds = new Set<string>();
  const normalizedSources: SecurityAuditSourceProvenance[] = [];
  for (const source of sources) {
    const { id, state, reason } = source;
    const ids = source.evidenceIds;
    if (ids.some((evidenceId) => !evidenceIds.has(evidenceId))) return undefined;
    if (sourceIds.has(id)) return undefined;
    sourceIds.add(id);
    for (const evidenceId of ids) {
      if (linkedEvidenceIds.has(evidenceId)) return undefined;
      linkedEvidenceIds.add(evidenceId);
    }
    normalizedSources.push({
      id,
      state,
      ...(reason === undefined ? {} : { reason }),
      evidenceIds: ids,
    });
  }
  if (linkedEvidenceIds.size !== evidenceIds.size) return undefined;
  if (lineageEvidence.some((item) => !item.sourceId || !sourceIds.has(item.sourceId)))
    return undefined;
  if (
    lineageEvidence.some(
      (item) =>
        !normalizedSources.some(
          (source) => source.id === item.sourceId && source.evidenceIds.includes(item.id),
        ),
    )
  )
    return undefined;
  return resultSources(evidence, normalizedSources);
}

/** Accept collector source records only when their presence matches the evidence boundary. */
function observationSources(
  value: unknown,
  lineageEvidence: readonly SecurityAuditEvidence[],
): readonly SecurityAuditSourceProvenance[] | undefined {
  if (value === undefined) return lineageEvidence.length === 0 ? [] : undefined;
  return Array.isArray(value) && value.every(isValidSource) ? value : undefined;
}

/** Omit evidence-linked sources when the engine safely excludes their evidence from a result. */
function resultSources(
  evidence: readonly SecurityAuditEvidence[],
  sources: readonly SecurityAuditSourceProvenance[],
): readonly SecurityAuditSourceProvenance[] {
  return evidence.length === 0
    ? sources.filter((source) => source.evidenceIds.length === 0)
    : sources;
}

/** Use declared evidence only when an engine path intentionally retained none but IDs remain safe to inspect. */
function evidenceForLineage(
  observation: Record<string, unknown>,
  evidence: readonly SecurityAuditEvidence[],
): readonly SecurityAuditEvidence[] {
  return evidence.length > 0 || !Array.isArray(observation.evidence)
    ? evidence
    : observation.evidence.every((item) => isRecord(item) && typeof item.id === 'string')
      ? (observation.evidence as readonly SecurityAuditEvidence[])
      : evidence;
}

/** Validate one serialized source boundary without accepting arbitrary host-derived identifiers. */
function isValidSource(value: unknown): value is SecurityAuditSourceProvenance {
  if (!isRecord(value) || !isSourceId(value.id) || !isSourceState(value.state)) return false;
  return (
    isSourceReason(value.reason) &&
    Array.isArray(value.evidenceIds) &&
    value.evidenceIds.every(isNonEmpty)
  );
}
/** Accept only stable collector IDs from the canonical source registry. */
function isSourceId(value: unknown): value is string {
  return isSecurityAuditSourceId(value);
}
/** Keep source states closed so arbitrary runtime values cannot cross into JSON. */
function isSourceState(value: unknown): value is SecurityAuditSourceProvenance['state'] {
  return [
    'completed',
    'missing',
    'permission-blocked',
    'timed-out',
    'aborted',
    'parse-invalid',
    'failed',
    'not-queried',
    'unsupported',
    'manual',
    'unclassified',
  ].includes(value as SecurityAuditSourceProvenance['state']);
}
/** Keep source reasons closed so manifests cannot carry collector-provided host details. */
function isSourceReason(value: unknown): value is SecurityAuditSourceProvenance['reason'] {
  return value === undefined || value === 'bounded-inventory';
}
/** Narrow untrusted JSON before reading source fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/** Accept a serializable non-empty evidence identifier. */
function isNonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
