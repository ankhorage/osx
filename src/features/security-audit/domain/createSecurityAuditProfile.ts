import type { SecurityAuditProfile } from '../../../types/securityAudit.js';

/*** Create the conservative baseline that reports only evidence-backed security outcomes. */
export function createSecurityAuditProfile(): SecurityAuditProfile {
  return {
    id: 'macos-informational',
    version: '1',
    title: 'macOS informational security baseline',
    description: 'Evidence-backed posture reporting without compliance or completeness claims.',
    baseline: 'macos-informational-v1',
  };
}
