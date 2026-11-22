import type {
  SecurityAuditObservation,
  SecurityAuditProfile,
} from '../../../types/securityAudit.js';
import { createApplicationPostureFacts } from '../domain/createApplicationPostureFacts.js';
import type { MacosSecurityCommandRunner } from '../ports/macosSecurityCommandRunner.js';
import {
  createSecurityObservation,
  createSecuritySourceProvenance,
  createUnknownSecurityObservation,
} from '../utils/createSecurityObservation.js';

const controlId = 'osi7-application-network-and-persistence';

/*** Collect redacted resolver, Gatekeeper, application-assessment, service, developer-listener, and persistence metadata without scanning the host. */
export async function collectApplicationPostureObservationAsync(
  runner: MacosSecurityCommandRunner,
  profile: SecurityAuditProfile,
  collectedAt: string,
  input: { readonly signal?: AbortSignal } = {},
): Promise<SecurityAuditObservation> {
  const [dns, proxy, gatekeeper, signing, applicationAssessment, disabledServices, listeners] =
    await collectApplicationPostureMetadataAsync(runner, input);
  const available = [
    dns,
    proxy,
    gatekeeper,
    signing,
    applicationAssessment,
    disabledServices,
    listeners,
  ].filter((result) => result.exitCode === 0);
  const sources = createSecuritySourceProvenance([
    { id: 'macos-posture:dns', result: dns },
    { id: 'macos-posture:application-proxy', result: proxy },
    { id: 'macos-posture:gatekeeper', result: gatekeeper },
    { id: 'macos-posture:application-signing', result: signing },
    { id: 'macos-posture:application-assessment', result: applicationAssessment },
    { id: 'macos-posture:application-disabled-services', result: disabledServices },
    { id: 'macos-posture:application-listeners', result: listeners },
  ]);
  if (available.length === 0) return createUnknownSecurityObservation(controlId, sources);
  return createSecurityObservation(
    controlId,
    profile,
    collectedAt,
    'application-posture-metadata',
    `${available.length} read-only application-posture metadata sources were available; resolver values, proxy endpoints, paths, and process identities were discarded.`,
    createApplicationPostureFacts({
      dnsAvailable: successfulAvailability(dns),
      proxy: successfulOutput(proxy),
      gatekeeper: successfulOutput(gatekeeper),
      signingAvailable: successfulAvailability(signing),
      applicationAssessmentAccepted: successfulAvailability(applicationAssessment),
      persistenceAvailable: successfulAvailability(disabledServices),
      listeners: successfulOutput(listeners),
    }),
    available.length === 7 ? 'applicable' : 'unknown',
    sources,
  );
}

/*** Read fixed local commands concurrently; no command output leaves this application boundary. */
async function collectApplicationPostureMetadataAsync(
  runner: MacosSecurityCommandRunner,
  input: { readonly signal?: AbortSignal },
) {
  return Promise.all([
    runner.runAsync(['/usr/sbin/scutil', '--dns'], input),
    runner.runAsync(['/usr/sbin/scutil', '--proxy'], input),
    runner.runAsync(['/usr/sbin/spctl', '--status'], input),
    runner.runAsync(
      ['/usr/bin/codesign', '-dv', '--verbose=2', '/System/Applications/Calculator.app'],
      input,
    ),
    runner.runAsync(
      ['/usr/sbin/spctl', '--assess', '--type', 'execute', '/System/Applications/Calculator.app'],
      input,
    ),
    runner.runAsync(['/bin/launchctl', 'print-disabled', 'system'], input),
    runner.runAsync(['/usr/sbin/netstat', '-an', '-p', 'tcp'], input),
  ]);
}

/*** Exclude failed collector output so missing commands cannot become application-posture facts. */
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
