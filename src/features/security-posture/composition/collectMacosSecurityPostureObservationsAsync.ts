import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createMacosSecurityCommandRunner } from '../adapters/createMacosSecurityCommandRunner.js';
import { collectApplicationPostureObservationAsync } from '../application/collectApplicationPostureObservationAsync.js';
import { collectPresentationTrustObservationAsync } from '../application/collectPresentationTrustObservationAsync.js';
import { collectSessionExposureObservationAsync } from '../application/collectSessionExposureObservationAsync.js';

/*** Compose the three independent read-only L5-L7 collectors without changing audit routing or control policy. */
export async function collectMacosSecurityPostureObservationsAsync(
  profile: SecurityAuditProfile,
  collectedAt = new Date().toISOString(),
): Promise<readonly SecurityAuditObservation[]> {
  const runner = createMacosSecurityCommandRunner();
  return Promise.all([
    collectSessionExposureObservationAsync(runner, profile, collectedAt),
    collectPresentationTrustObservationAsync(runner, profile, collectedAt),
    collectApplicationPostureObservationAsync(runner, profile, collectedAt),
  ]);
}
