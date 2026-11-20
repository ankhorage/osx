import type {
  SecurityAuditEvidence,
  SecurityAuditEvidenceBooleanFact,
  SecurityAuditObservation,
  SecurityAuditProfile,
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
      {
        id: `macos-posture:${controlId}`,
        state: 'completed',
        evidenceIds: [evidence.id],
      },
    ],
  };
}

/*** Represent absent, denied, or unsupported host evidence without manufacturing a security conclusion. */
export function createUnknownSecurityObservation(controlId: string): SecurityAuditObservation {
  return { controlId, applicability: 'unknown', access: 'available', evidence: [], sources: [] };
}
