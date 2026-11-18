import type { SecurityAuditEvidenceBooleanFact } from '../../../types/securityAudit.js';

/*** Create trust and proxy indicators without preserving certificate or credential-store data. */
export function createPresentationTrustFacts(input: {
  readonly trustSettingsAvailable: true | undefined;
  readonly keychainMetadataAvailable: true | undefined;
  readonly proxy: string | undefined;
}): readonly SecurityAuditEvidenceBooleanFact[] {
  return [
    ...(input.trustSettingsAvailable === undefined
      ? []
      : [{ id: 'trust-settings-metadata-observable', value: input.trustSettingsAvailable }]),
    ...(input.keychainMetadataAvailable === undefined
      ? []
      : [{ id: 'keychain-metadata-observable', value: input.keychainMetadataAvailable }]),
    ...(input.proxy === undefined
      ? []
      : [
          {
            id: 'explicit-interception-proxy-not-configured',
            value: !hasEnabledProxy(input.proxy),
          },
        ]),
    { id: 'certificate-validity-not-enumerated', value: false },
  ];
}

/*** Treat any enabled HTTP(S), SOCKS, or PAC proxy as an inspection indicator, not proof of interception. */
function hasEnabledProxy(output: string): boolean {
  return /(?:HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable)\s*:\s*1\b/u.test(output);
}
