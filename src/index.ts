/*** Provide reusable local storage inspection and approval boundaries. */
export { collectMacosHostSecurityObservations } from './features/security-audit/adapters/outbound/collectMacosHostSecurityObservations.js';
export { collectMacosPhysicalAndLinkObservations } from './features/security-audit/adapters/outbound/collectMacosPhysicalAndLinkObservations.js';
export {
  createMacosSecurityAuditCommandRunner,
  type MacosSecurityAuditCommandResult,
  type MacosSecurityAuditCommandRunner,
} from './features/security-audit/adapters/outbound/createMacosSecurityAuditCommandRunner.js';
export { runSecurityAudit } from './features/security-audit/application/runSecurityAudit.js';
export { serializeSecurityAuditReport } from './features/security-audit/application/serializeSecurityAuditReport.js';
export { createDefaultSecurityAuditReport } from './features/security-audit/composition/createDefaultSecurityAuditReport.js';
export {
  createMacosHostSecuritySupportMatrix,
  type MacosHostSecuritySupport,
  type MacosHostSecuritySupportEntry,
} from './features/security-audit/domain/createMacosHostSecuritySupportMatrix.js';
export { createSecurityAuditCatalog } from './features/security-audit/domain/createSecurityAuditCatalog.js';
export { createSecurityAuditProfile } from './features/security-audit/domain/createSecurityAuditProfile.js';
export { cleanStorageAsync } from './features/storage/application/cleanStorageAsync.js';
export { scanOrphanedApplicationsAsync } from './features/storage/application/scanOrphanedApplicationsAsync.js';
export { scanStorageAsync } from './features/storage/composition/scanStorageAsync.js';
export {
  createSimctlRuntimeScanner,
  parseRuntimeInventoryAsync,
} from './features/xcode-runtimes/adapters/outbound/createSimctlRuntimeScanner.js';
export { scanXcodeRuntimesAsync } from './features/xcode-runtimes/composition/scanXcodeRuntimesAsync.js';
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
export type { SimctlHost, XcodeRuntime } from './types/xcodeRuntime.js';
