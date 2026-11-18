import type { SecurityAuditReport } from '../../../types/securityAudit.js';
import { runSecurityAudit } from '../application/runSecurityAudit.js';
import { createSecurityAuditCatalog } from '../domain/createSecurityAuditCatalog.js';
import { createSecurityAuditProfile } from '../domain/createSecurityAuditProfile.js';

/*** Create the deterministic no-collector report, explicitly marking every unimplemented control unsupported. */
export function createDefaultSecurityAuditReport(): SecurityAuditReport {
  return runSecurityAudit(createSecurityAuditCatalog(), createSecurityAuditProfile(), []);
}
