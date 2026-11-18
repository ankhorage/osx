/*** Provide reusable local storage inspection and approval boundaries. */
export { runSecurityAudit } from './features/security-audit/application/runSecurityAudit.js';
export { serializeSecurityAuditReport } from './features/security-audit/application/serializeSecurityAuditReport.js';
export { createDefaultSecurityAuditReport } from './features/security-audit/composition/createDefaultSecurityAuditReport.js';
export { createSecurityAuditCatalog } from './features/security-audit/domain/createSecurityAuditCatalog.js';
export { createSecurityAuditProfile } from './features/security-audit/domain/createSecurityAuditProfile.js';
export { collectApplicationPostureObservationAsync } from './features/security-posture/application/collectApplicationPostureObservationAsync.js';
export { collectPresentationTrustObservationAsync } from './features/security-posture/application/collectPresentationTrustObservationAsync.js';
export { collectSessionExposureObservationAsync } from './features/security-posture/application/collectSessionExposureObservationAsync.js';
export { collectMacosSecurityPostureObservationsAsync } from './features/security-posture/composition/collectMacosSecurityPostureObservationsAsync.js';
export { cleanStorageAsync } from './features/storage/application/cleanStorageAsync.js';
export { scanOrphanedApplicationsAsync } from './features/storage/application/scanOrphanedApplicationsAsync.js';
export { scanStorageAsync } from './features/storage/composition/scanStorageAsync.js';
export type {
  OrphanedApplicationEvidenceAvailability,
  OrphanedApplicationEvidenceSource,
  OrphanedApplicationHost,
  OrphanedApplicationObservation,
} from './types/orphanedApplications.js';
export type {
  SecurityAuditApplicability,
  SecurityAuditBaseline,
  SecurityAuditBaselinePredicate,
  SecurityAuditCategory,
  SecurityAuditConfidence,
  SecurityAuditControl,
  SecurityAuditCoverage,
  SecurityAuditCoverageMatrix,
  SecurityAuditCoverageTotals,
  SecurityAuditDetectionMode,
  SecurityAuditEvidence,
  SecurityAuditEvidenceBooleanFact,
  SecurityAuditExpectedBooleanFact,
  SecurityAuditObservation,
  SecurityAuditOutcome,
  SecurityAuditProfile,
  SecurityAuditRecommendation,
  SecurityAuditReport,
  SecurityAuditResult,
  SecurityAuditSeverity,
} from './types/securityAudit.js';
export type {
  StorageCandidate,
  StorageCleanupResult,
  StorageDecisions,
  StorageExecution,
  StorageOperations,
} from './types/storage.js';
