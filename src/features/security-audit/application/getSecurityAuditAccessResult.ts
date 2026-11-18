import type {
  SecurityAuditBaselineEvaluation,
  SecurityAuditCoverage,
} from '../../../types/securityAudit.js';

type SecurityAuditAccessResult = readonly [
  Extract<SecurityAuditCoverage, 'incomplete' | 'permission-blocked'>,
  Extract<
    SecurityAuditBaselineEvaluation['status'],
    'incomplete-evidence' | 'inaccessible-evidence'
  >,
];

/*** Classify explicitly incomplete access without treating it as either invalid or permission-blocked. */
export function getSecurityAuditAccessResult(
  observation: object,
): SecurityAuditAccessResult | undefined {
  const access: unknown = Object.getOwnPropertyDescriptor(observation, 'access')?.value;
  if (access === 'permission-blocked') return ['permission-blocked', 'inaccessible-evidence'];
  if (access === 'incomplete') return ['incomplete', 'incomplete-evidence'];
  return undefined;
}
