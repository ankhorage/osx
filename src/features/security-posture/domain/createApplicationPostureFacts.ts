import type { SecurityAuditEvidenceBooleanFact } from '../../../types/securityAudit.js';

/** Create resolver, Gatekeeper, persistence, and developer-service indicators without retaining raw host metadata. */
export function createApplicationPostureFacts(input: {
  readonly dnsAvailable: boolean;
  readonly proxy: string;
  readonly gatekeeper: string;
  readonly signingAvailable: boolean;
  readonly notarizationAccepted: boolean;
  readonly persistenceAvailable: boolean;
  readonly listeners: string;
}): readonly SecurityAuditEvidenceBooleanFact[] {
  return [
    { id: 'resolver-metadata-observable', value: input.dnsAvailable },
    { id: 'application-proxy-not-configured', value: !hasEnabledProxy(input.proxy) },
    { id: 'gatekeeper-assessments-enabled', value: /assessments enabled/i.test(input.gatekeeper) },
    { id: 'system-application-signing-observable', value: input.signingAvailable },
    {
      id: 'system-application-notarization-assessment-accepted',
      value: input.notarizationAccepted,
    },
    { id: 'system-persistence-metadata-observable', value: input.persistenceAvailable },
    {
      id: 'common-developer-listeners-not-observed',
      value: !hasDeveloperListener(input.listeners),
    },
  ];
}

/** Detect only configured proxy modes; a proxy can be legitimate and is not called malicious. */
function hasEnabledProxy(output: string): boolean {
  return /(?:HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)\s*:\s*1\b/u.test(output);
}

/** Detect conventional developer ports locally without preserving the listener address, process, or command line. */
function hasDeveloperListener(output: string): boolean {
  return output.split(/\r?\n/u).some((line) => /\.(?:3000|4173|5173|8000|8080)\s/i.test(line));
}
