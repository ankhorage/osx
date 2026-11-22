import type {
  SecurityAuditEvidence,
  SecurityAuditEvidenceBooleanFact,
  SecurityAuditObservation,
  SecurityAuditProfile,
  SecurityAuditSourceProvenance,
} from '../../../types/securityAudit.js';

/*** Create one redacted observation whose raw macOS command output never crosses the adapter boundary. */
export function createSecurityObservation(
  controlId: string,
  profile: SecurityAuditProfile,
  collectedAt: string,
  kind: string,
  summary: string,
  facts: readonly SecurityAuditEvidenceBooleanFact[],
  applicability: SecurityAuditObservation['applicability'] = 'applicable',
  sourceStates: readonly SecurityAuditSourceProvenance[],
): SecurityAuditObservation {
  const evidence: SecurityAuditEvidence = {
    id: `${controlId}-metadata`,
    sourceId: `macos-posture:${controlId}`,
    controlId,
    profileId: profile.id,
    baselineVersion: profile.baseline,
    kind,
    summary,
    collectedAt,
    redacted: true,
    facts,
  };
  return {
    controlId,
    applicability,
    access: 'available',
    evidence: [evidence],
    sources: [
      ...sourceStates,
      {
        id: `macos-posture:${controlId}`,
        state: 'completed',
        evidenceIds: [evidence.id],
      },
    ],
  };
}

/*** Represent absent, denied, or unsupported host evidence without manufacturing a security conclusion. */
export function createUnknownSecurityObservation(
  controlId: string,
  sourceStates: readonly SecurityAuditSourceProvenance[],
): SecurityAuditObservation {
  return {
    controlId,
    applicability: 'unknown',
    access: 'incomplete',
    evidence: [],
    sources: sourceStates,
  };
}

/** Preserve each command attempt when this legacy boundary supplies no trustworthy failure reason. */
export function createSecuritySourceProvenance(
  sources: readonly {
    readonly id: string;
    readonly result: { readonly exitCode: number };
  }[],
): readonly SecurityAuditSourceProvenance[] {
  return sources.map(({ id, result }) => ({
    id,
    state: result.exitCode === 0 ? 'completed' : 'unclassified',
    evidenceIds: [],
  }));
}
