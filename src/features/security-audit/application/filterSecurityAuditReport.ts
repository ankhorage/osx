import type { SecurityAuditReport } from '../../../types/securityAudit.js';
import { createSecurityAuditCoverageMatrix } from '../domain/createSecurityAuditCoverageMatrix.js';
import { createSecurityAuditManifest } from './createSecurityAuditManifest.js';

/*** Limit a report to one requested audit chapter while preserving explicit zero coverage elsewhere. */
export function filterSecurityAuditReport(
  report: SecurityAuditReport,
  matches: (result: SecurityAuditReport['results'][number]) => boolean,
): SecurityAuditReport {
  const results = report.results.filter(matches);
  return {
    ...report,
    results,
    coverage: createSecurityAuditCoverageMatrix(results),
    manifest: createSecurityAuditManifest(report.profile, results),
  };
}
