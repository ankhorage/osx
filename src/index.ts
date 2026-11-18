/*** Provide reusable local storage inspection and approval boundaries. */
export { runSecurityAudit } from './features/security-audit/application/runSecurityAudit.js';
export { serializeSecurityAuditReport } from './features/security-audit/application/serializeSecurityAuditReport.js';
export { createDefaultSecurityAuditReport } from './features/security-audit/composition/createDefaultSecurityAuditReport.js';
export { createSecurityAuditCatalog } from './features/security-audit/domain/createSecurityAuditCatalog.js';
export { createSecurityAuditProfile } from './features/security-audit/domain/createSecurityAuditProfile.js';
export { collectSecurityNetworkAsync } from './features/security-network/application/collectSecurityNetworkAsync.js';
export { collectDefaultSecurityNetworkAsync } from './features/security-network/composition/collectDefaultSecurityNetworkAsync.js';
export type {
  SecurityNetworkCommandResult,
  SecurityNetworkHost,
} from './features/security-network/ports/securityNetworkHost.js';
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
  SecurityNetworkApplicationFirewallEvidence,
  SecurityNetworkEvidence,
  SecurityNetworkEvidenceAvailability,
  SecurityNetworkLayer3Evidence,
  SecurityNetworkLayer4Evidence,
  SecurityNetworkPacketFilterEvidence,
  SecurityNetworkSetting,
} from './types/securityNetwork.js';
export type {
  StorageCandidate,
  StorageCleanupResult,
  StorageDecisions,
  StorageExecution,
  StorageOperations,
} from './types/storage.js';
