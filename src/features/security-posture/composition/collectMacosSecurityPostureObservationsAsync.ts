import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createMacosSecurityCommandRunner } from '../adapters/createMacosSecurityCommandRunner.js';
import { collectApplicationPostureObservationAsync } from '../application/collectApplicationPostureObservationAsync.js';
import { collectPresentationTrustObservationAsync } from '../application/collectPresentationTrustObservationAsync.js';
import { collectSessionExposureObservationAsync } from '../application/collectSessionExposureObservationAsync.js';
import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';

/*** Compose the three independent read-only L5-L7 collectors without changing audit routing or control policy. */
export async function collectMacosSecurityPostureObservationsAsync(
  profile: SecurityAuditProfile,
  collectedAt = new Date().toISOString(),
  input: {
    readonly controlIds?: ReadonlySet<string>;
    readonly runner?: MacosSecurityCommandRunner;
    readonly signal?: AbortSignal;
  } = {},
): Promise<readonly SecurityAuditObservation[]> {
  const runner = input.runner ?? createMacosSecurityCommandRunner();
  const collectors = [
    ['osi5-remote-session-services', collectSessionExposureObservationAsync],
    ['osi6-presentation-trust', collectPresentationTrustObservationAsync],
    ['osi7-application-network-and-persistence', collectApplicationPostureObservationAsync],
  ] as const;
  return Promise.all(
    collectors
      .filter(([controlId]) => input.controlIds?.has(controlId) ?? true)
      .map(([, collect]) => collect(runner, profile, collectedAt, { signal: input.signal })),
  );
}
