import type {
  SecurityAuditBaseline,
  SecurityAuditBaselineEvaluation,
  SecurityAuditEvidence,
} from '../../../types/securityAudit.js';

/*** Preserve the selected baseline and its exact evidence identifiers in every report result. */
export function createSecurityAuditBaselineEvaluation(
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
