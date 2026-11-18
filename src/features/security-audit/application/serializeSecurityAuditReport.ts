import type { SecurityAuditReport } from '../../../types/securityAudit.js';

/*** Serialize a report with stable indentation and a trailing newline for machine consumers. */
export function serializeSecurityAuditReport(report: SecurityAuditReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}
