import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { createSecurityAuditCatalog } from '../../../../features/security-audit/domain/createSecurityAuditCatalog.js';

/*** List the fixed audit catalog and never claim that catalog membership means collector support. */
export function list(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || (request.argv.length === 1 && request.argv[0] !== '--json')) {
    request.context.writeStderr('Usage: ankh osx security controls list [--json]\n');
    return Promise.resolve({ exitCode: 1 });
  }
  const controls = createSecurityAuditCatalog().map((control) => ({
    control,
    collector: collectorPresence(control.id),
    baseline: control.baselines.length === 0 ? 'none' : 'versioned',
  }));
  if (request.argv.includes('--json'))
    request.context.writeStdout(`${JSON.stringify({ controls }, null, 2)}\n`);
  else
    for (const item of controls) {
      request.context.writeStdout(`${item.control.id}: ${item.control.title}\n`);
      request.context.writeStdout(`  ${item.control.description}\n`);
      request.context.writeStdout(
        `  Detection: ${item.control.detectionMode}; collector: ${item.collector}; baseline: ${item.baseline}.\n`,
      );
      request.context.writeStdout(
        `  Recommendation: ${item.control.recommendation.manualRemediation}\n`,
      );
    }
  return Promise.resolve({ exitCode: 0 });
}

/** State static collector presence separately from live host evidence and policy verification. */
function collectorPresence(controlId: string): 'present' | 'not-implemented' {
  return implementedCollectorControlIds.has(controlId) ? 'present' : 'not-implemented';
}

const implementedCollectorControlIds = new Set([
  'osi1-physical-interface-inventory',
  'osi2-link-security',
  'osi3-routing-and-filtering',
  'osi4-service-exposure',
  'osi5-remote-session-services',
  'osi6-presentation-trust',
  'osi7-application-network-and-persistence',
  'cross-layer-hardware-startup-trust',
  'cross-layer-disk-data',
  'cross-layer-identity-access',
  'cross-layer-malware-integrity',
  'cross-layer-backups-resilience-logging',
  'cross-layer-enterprise-policy',
]);
