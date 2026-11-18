import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createSessionExposureFacts } from '../domain/createSessionExposureFacts.js';
import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';
import {
  createSecurityObservation,
  createUnknownSecurityObservation,
} from '../utils/createSecurityObservation.js';

const controlId = 'osi5-remote-session-services';

/*** Collect redacted Remote Login, sharing, and session-exposure indicators without enumerating people or sessions. */
export async function collectSessionExposureObservationAsync(
  runner: MacosSecurityCommandRunner,
  profile: SecurityAuditProfile,
  collectedAt: string,
): Promise<SecurityAuditObservation> {
  const [remoteLogin, sharing, disabledServices, listeners] = await Promise.all([
    runner.runAsync(['/usr/sbin/systemsetup', '-getremotelogin']),
    runner.runAsync(['/usr/sbin/sharing', '-l']),
    runner.runAsync(['/bin/launchctl', 'print-disabled', 'system']),
    runner.runAsync(['/usr/sbin/netstat', '-an', '-p', 'tcp']),
  ]);
  const available = [remoteLogin, sharing, disabledServices, listeners].filter(
    (result) => result.exitCode === 0,
  );
  if (available.length === 0) return createUnknownSecurityObservation(controlId);
  return createSecurityObservation(
    controlId,
    profile,
    collectedAt,
    'remote-session-metadata',
    `${available.length} read-only remote-session metadata sources were available; no account, address, or session identity was retained.`,
    createSessionExposureFacts({
      remoteLogin: successfulOutput(remoteLogin),
      sharing: successfulOutput(sharing),
      disabledServices: successfulOutput(disabledServices),
      listeners: successfulOutput(listeners),
    }),
    available.length === 4 ? 'applicable' : 'unknown',
  );
}

/*** Exclude failed collector output so absence never becomes a remote-session security fact. */
function successfulOutput(result: {
  readonly exitCode: number;
  readonly stdout: string;
}): string | undefined {
  return result.exitCode === 0 ? result.stdout : undefined;
}
