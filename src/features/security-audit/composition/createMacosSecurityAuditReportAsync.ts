import type { SecurityAuditReport } from '../../../types/securityAudit.js';
import { collectDefaultSecurityNetworkAsync } from '../../security-network/composition/collectDefaultSecurityNetworkAsync.js';
import { collectMacosSecurityPostureObservationsAsync } from '../../security-posture/composition/collectMacosSecurityPostureObservationsAsync.js';
import { collectMacosHostSecurityObservations } from '../adapters/outbound/collectMacosHostSecurityObservations.js';
import { collectMacosPhysicalAndLinkObservations } from '../adapters/outbound/collectMacosPhysicalAndLinkObservations.js';
import { createMacosSecurityAuditCommandRunner } from '../adapters/outbound/createMacosSecurityAuditCommandRunner.js';
import { createSecurityNetworkAuditObservations } from '../application/createSecurityNetworkAuditObservations.js';
import { runSecurityAudit } from '../application/runSecurityAudit.js';
import { createSecurityAuditCatalog } from '../domain/createSecurityAuditCatalog.js';
import { createSecurityAuditProfile } from '../domain/createSecurityAuditProfile.js';

/** Compose all passive macOS collectors for the host-aware CLI pathway without changing the portable default report. */
export async function createMacosSecurityAuditReportAsync(): Promise<SecurityAuditReport> {
  const profile = createSecurityAuditProfile();
  const collectedAt = new Date().toISOString();
  const runner = createMacosSecurityAuditCommandRunner();
  if (runner.platform !== 'darwin')
    return runSecurityAudit(createSecurityAuditCatalog(), profile, [
      ...collectMacosPhysicalAndLinkObservations({ runner, profile, collectedAt }),
      ...collectMacosHostSecurityObservations({ runner, profile, collectedAt }),
    ]);
  const [networkEvidence, postureObservations] = await Promise.all([
    collectDefaultSecurityNetworkAsync(),
    collectMacosSecurityPostureObservationsAsync(profile, collectedAt),
  ]);
  return runSecurityAudit(createSecurityAuditCatalog(), profile, [
    ...collectMacosPhysicalAndLinkObservations({ runner, profile, collectedAt }),
    ...createSecurityNetworkAuditObservations(networkEvidence, profile),
    ...postureObservations,
    ...collectMacosHostSecurityObservations({ runner, profile, collectedAt }),
  ]);
}
