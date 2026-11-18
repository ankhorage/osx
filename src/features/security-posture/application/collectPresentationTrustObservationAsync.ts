import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createPresentationTrustFacts } from '../domain/createPresentationTrustFacts.js';
import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';
import {
  createSecurityObservation,
  createUnknownSecurityObservation,
} from '../utils/createSecurityObservation.js';

const controlId = 'osi6-presentation-trust';

/*** Collect local trust-store and proxy indicators without exporting certificates, keychain records, or credentials. */
export async function collectPresentationTrustObservationAsync(
  runner: MacosSecurityCommandRunner,
  profile: SecurityAuditProfile,
  collectedAt: string,
): Promise<SecurityAuditObservation> {
  const [trustSettings, keychains, proxy] = await Promise.all([
    runner.runAsync(['/usr/bin/security', 'dump-trust-settings', '-d']),
    runner.runAsync(['/usr/bin/security', 'list-keychains', '-d', 'user']),
    runner.runAsync(['/usr/sbin/scutil', '--proxy']),
  ]);
  const available = [trustSettings, keychains, proxy].filter((result) => result.exitCode === 0);
  if (available.length === 0) return createUnknownSecurityObservation(controlId);
  return createSecurityObservation(
    controlId,
    profile,
    collectedAt,
    'presentation-trust-metadata',
    `${available.length} read-only trust metadata sources were available; certificate subjects, credential-store paths, and credentials were discarded.`,
    createPresentationTrustFacts({
      trustSettingsAvailable: successfulAvailability(trustSettings),
      keychainMetadataAvailable: successfulAvailability(keychains),
      proxy: successfulOutput(proxy),
    }),
    available.length === 3 ? 'applicable' : 'unknown',
  );
}

/*** Exclude failed proxy output so unavailable trust sources cannot imply no proxy. */
function successfulOutput(result: {
  readonly exitCode: number;
  readonly stdout: string;
}): string | undefined {
  return result.exitCode === 0 ? result.stdout : undefined;
}

/*** Represent successful source availability without converting a failed command into a negative fact. */
function successfulAvailability(result: { readonly exitCode: number }): true | undefined {
  return result.exitCode === 0 ? true : undefined;
}
