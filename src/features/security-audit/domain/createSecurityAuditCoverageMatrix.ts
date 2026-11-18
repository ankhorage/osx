import type {
  SecurityAuditCoverage,
  SecurityAuditCoverageMatrix,
  SecurityAuditCoverageTotals,
  SecurityAuditResult,
} from '../../../types/securityAudit.js';

/*** Count primary-category coverage without letting cross references inflate completeness. */
export function createSecurityAuditCoverageMatrix(
  results: readonly SecurityAuditResult[],
): SecurityAuditCoverageMatrix {
  const osi = Object.fromEntries(
    [1, 2, 3, 4, 5, 6, 7].map((layer) => [layer, emptyTotals()]),
  ) as Record<1 | 2 | 3 | 4 | 5 | 6 | 7, SecurityAuditCoverageTotals>;
  const themes = [
    'hardware-startup-trust',
    'disk-data',
    'identity-access',
    'privacy-permissions',
    'malware-integrity',
    'patching-exposure',
    'network-trust',
    'development-supply-chain',
    'backups-resilience-logging',
    'enterprise-policy',
  ] as const;
  const crossLayer = Object.fromEntries(themes.map((theme) => [theme, emptyTotals()])) as Record<
    (typeof themes)[number],
    SecurityAuditCoverageTotals
  >;
  for (const result of results) {
    const category = result.control.primaryCategory;
    if (category.kind === 'osi')
      osi[category.layer] = addCoverage(osi[category.layer], result.coverage);
    else crossLayer[category.theme] = addCoverage(crossLayer[category.theme], result.coverage);
  }
  return { osi, crossLayer };
}

/** Create an empty immutable-shaped coverage counter. */
function emptyTotals(): SecurityAuditCoverageTotals {
  return { implemented: 0, supported: 0, unsupported: 0, incomplete: 0, permissionBlocked: 0 };
}

/** Increment the one coverage state represented by a control result. */
function addCoverage(
  totals: SecurityAuditCoverageTotals,
  coverage: SecurityAuditCoverage,
): SecurityAuditCoverageTotals {
  if (coverage === 'implemented') return { ...totals, implemented: totals.implemented + 1 };
  if (coverage === 'supported') return { ...totals, supported: totals.supported + 1 };
  if (coverage === 'incomplete') return { ...totals, incomplete: totals.incomplete + 1 };
  if (coverage === 'permission-blocked')
    return { ...totals, permissionBlocked: totals.permissionBlocked + 1 };
  return { ...totals, unsupported: totals.unsupported + 1 };
}
