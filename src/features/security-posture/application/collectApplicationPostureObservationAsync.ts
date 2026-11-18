import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createApplicationPostureFacts } from '../domain/createApplicationPostureFacts.js';
import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';
import {
  createSecurityObservation,
  createUnknownSecurityObservation,
} from '../utils/createSecurityObservation.js';

const controlId = 'osi7-application-network-and-persistence';

/*** Collect redacted resolver, Gatekeeper, service, developer-listener, and persistence metadata without scanning the host. */
export async function collectApplicationPostureObservationAsync(
  runner: MacosSecurityCommandRunner,
  profile: SecurityAuditProfile,
  collectedAt: string,
): Promise<SecurityAuditObservation> {
  const [dns, proxy, gatekeeper, signing, notarization, disabledServices, listeners] =
    await collectApplicationPostureMetadataAsync(runner);
  const available = [
    dns,
    proxy,
    gatekeeper,
    signing,
    notarization,
    disabledServices,
    listeners,
  ].filter((result) => result.exitCode === 0);
  if (available.length === 0) return createUnknownSecurityObservation(controlId);
  return createSecurityObservation(
    controlId,
    profile,
    collectedAt,
    'application-posture-metadata',
    `${available.length} read-only application-posture metadata sources were available; resolver values, proxy endpoints, paths, and process identities were discarded.`,
    createApplicationPostureFacts({
      dnsAvailable: dns.exitCode === 0,
      proxy: proxy.stdout,
      gatekeeper: gatekeeper.stdout,
      signingAvailable: signing.exitCode === 0,
      notarizationAccepted: notarization.exitCode === 0,
      persistenceAvailable: disabledServices.exitCode === 0,
      listeners: listeners.stdout,
    }),
  );
}

/** Read fixed local commands concurrently; no command output leaves this application boundary. */
async function collectApplicationPostureMetadataAsync(runner: MacosSecurityCommandRunner) {
  return Promise.all([
    runner.runAsync(['/usr/sbin/scutil', '--dns']),
    runner.runAsync(['/usr/sbin/scutil', '--proxy']),
    runner.runAsync(['/usr/sbin/spctl', '--status']),
    runner.runAsync([
      '/usr/bin/codesign',
      '-dv',
      '--verbose=2',
      '/System/Applications/Calculator.app',
    ]),
    runner.runAsync([
      '/usr/sbin/spctl',
      '--assess',
      '--type',
      'execute',
      '/System/Applications/Calculator.app',
    ]),
    runner.runAsync(['/bin/launchctl', 'print-disabled', 'system']),
    runner.runAsync(['/usr/sbin/netstat', '-an', '-p', 'tcp']),
  ]);
}
