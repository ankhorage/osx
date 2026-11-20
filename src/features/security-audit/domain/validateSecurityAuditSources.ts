import type {
  SecurityAuditEvidence,
  SecurityAuditSourceProvenance,
} from '../../../types/securityAudit.js';

/*** Validate safe, complete evidence-to-source provenance supplied by a collector adapter. */
export function validateSecurityAuditSources(
  observation: unknown,
  evidence: readonly SecurityAuditEvidence[],
): readonly SecurityAuditSourceProvenance[] | undefined {
  if (observation === undefined) return [];
  if (!isRecord(observation)) return undefined;
  if (observation.sources === undefined) return evidence.length === 0 ? [] : undefined;
  if (!Array.isArray(observation.sources)) return undefined;
  const evidenceIds = new Set(evidence.map((item) => item.id));
  const sourceIds = new Set<string>();
  const linkedEvidenceIds = new Set<string>();
  const { sources } = observation;
  if (!sources.every(isValidSource)) return undefined;
  const normalizedSources: SecurityAuditSourceProvenance[] = [];
  for (const source of sources) {
    const { id, state } = source;
    const ids = source.evidenceIds.filter((evidenceId) => evidenceIds.has(evidenceId));
    if (sourceIds.has(id)) return undefined;
    sourceIds.add(id);
    for (const evidenceId of ids) {
      if (linkedEvidenceIds.has(evidenceId)) return undefined;
      linkedEvidenceIds.add(evidenceId);
    }
    normalizedSources.push({ id, state, evidenceIds: ids });
  }
  if (linkedEvidenceIds.size !== evidenceIds.size) return undefined;
  if (evidence.some((item) => !item.sourceId || !sourceIds.has(item.sourceId))) return undefined;
  if (
    evidence.some(
      (item) =>
        !normalizedSources.some(
          (source) => source.id === item.sourceId && source.evidenceIds.includes(item.id),
        ),
    )
  )
    return undefined;
  return normalizedSources;
}

/** Validate one serialized source boundary without accepting arbitrary host-derived identifiers. */
function isValidSource(value: unknown): value is SecurityAuditSourceProvenance {
  if (!isRecord(value) || !isSourceId(value.id) || !isSourceState(value.state)) return false;
  return Array.isArray(value.evidenceIds) && value.evidenceIds.every(isNonEmpty);
}
/** Accept registered namespaces and stable tokens only. */
function isSourceId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^(?:macos-(?:host|network|passive|posture)|platform|test):[a-z][a-z0-9-]*$/.test(value)
  );
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
/** Narrow untrusted JSON before reading source fields. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/** Accept a serializable non-empty evidence identifier. */
function isNonEmpty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
