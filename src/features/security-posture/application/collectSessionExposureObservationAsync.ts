import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createSessionExposureFacts } from '../domain/createSessionExposureFacts.js';
import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';
import {
  createSecurityObservation,
  createSecuritySourceProvenance,
  createUnknownSecurityObservation,
} from '../utils/createSecurityObservation.js';

const controlId = 'osi5-remote-session-services';

/*** Collect redacted Remote Login, sharing, and session-exposure indicators without enumerating people or sessions. */
export async function collectSessionExposureObservationAsync(
  runner: MacosSecurityCommandRunner,
  profile: SecurityAuditProfile,
  collectedAt: string,
  input: { readonly signal?: AbortSignal } = {},
): Promise<SecurityAuditObservation> {
  const [remoteLogin, sharing, disabledServices, listeners] = await Promise.all([
    runner.runAsync(['/usr/sbin/systemsetup', '-getremotelogin'], input),
    runner.runAsync(['/usr/sbin/sharing', '-l'], input),
    runner.runAsync(['/bin/launchctl', 'print-disabled', 'system'], input),
    runner.runAsync(['/usr/sbin/netstat', '-an', '-p', 'tcp'], input),
  ]);
  const available = [remoteLogin, sharing, disabledServices, listeners].filter(
    (result) => result.exitCode === 0,
  );
  const sources = createSecuritySourceProvenance([
    { id: 'macos-posture:remote-login', result: remoteLogin },
    { id: 'macos-posture:sharing', result: sharing },
    { id: 'macos-posture:session-disabled-services', result: disabledServices },
    { id: 'macos-posture:session-listeners', result: listeners },
  ]);
  if (available.length === 0) return createUnknownSecurityObservation(controlId, sources);
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
    sources,
  );
}

/*** Exclude failed collector output so absence never becomes a remote-session security fact. */
function successfulOutput(result: {
  readonly exitCode: number;
  readonly stdout: string;
}): string | undefined {
  return result.exitCode === 0 ? result.stdout : undefined;
}
