import type { SecurityAuditEvidenceBooleanFact } from '../../../types/securityAudit.js';

/*** Create resolver, Gatekeeper, persistence, and developer-service indicators without retaining raw host metadata. */
export function createApplicationPostureFacts(input: {
  readonly dnsAvailable: true | undefined;
  readonly proxy: string | undefined;
  readonly gatekeeper: string | undefined;
  readonly signingAvailable: true | undefined;
  readonly applicationAssessmentAccepted: true | undefined;
  readonly persistenceAvailable: true | undefined;
  readonly listeners: string | undefined;
}): readonly SecurityAuditEvidenceBooleanFact[] {
  return [
    ...(input.dnsAvailable === undefined
      ? []
      : [{ id: 'resolver-metadata-observable', value: input.dnsAvailable }]),
    ...(input.proxy === undefined
      ? []
      : [{ id: 'application-proxy-not-configured', value: !hasEnabledProxy(input.proxy) }]),
    ...(input.gatekeeper === undefined
      ? []
      : [
          {
            id: 'gatekeeper-assessments-enabled',
            value: /assessments enabled/i.test(input.gatekeeper),
          },
        ]),
    ...(input.signingAvailable === undefined
      ? []
      : [{ id: 'system-application-signing-observable', value: input.signingAvailable }]),
    ...(input.applicationAssessmentAccepted === undefined
      ? []
      : [
          {
            id: 'system-application-assessment-accepted',
            value: input.applicationAssessmentAccepted,
          },
        ]),
    ...(input.persistenceAvailable === undefined
      ? []
      : [{ id: 'system-persistence-metadata-observable', value: input.persistenceAvailable }]),
    ...(input.listeners === undefined
      ? []
      : [
          {
            id: 'common-developer-listeners-not-observed',
            value: !hasDeveloperListener(input.listeners),
          },
        ]),
  ];
}

/*** Detect only configured proxy modes; a proxy can be legitimate and is not called malicious. */
function hasEnabledProxy(output: string): boolean {
  return /(?:HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)\s*:\s*1\b/u.test(output);
}

/*** Detect conventional developer ports locally without preserving the listener address, process, or command line. */
function hasDeveloperListener(output: string): boolean {
  return output.split(/\r?\n/u).some((line) => /\.(?:3000|4173|5173|8000|8080)\s/i.test(line));
}
