import type { SecurityAuditEvidenceBooleanFact } from '../../../types/securityAudit.js';

/*** Create session-exposure facts from transient command output without retaining identifiers or endpoints. */
export function createSessionExposureFacts(input: {
  readonly remoteLogin: string | undefined;
  readonly sharing: string | undefined;
  readonly disabledServices: string | undefined;
  readonly listeners: string | undefined;
}): readonly SecurityAuditEvidenceBooleanFact[] {
  return [
    ...(input.remoteLogin === undefined
      ? []
      : [{ id: 'remote-login-disabled', value: /remote login:\s*off\b/i.test(input.remoteLogin) }]),
    ...(input.sharing === undefined
      ? []
      : [
          {
            id: 'screen-sharing-not-advertised',
            value: !mentions(input.sharing, 'screen sharing'),
          },
          {
            id: 'remote-management-not-advertised',
            value: !mentions(input.sharing, 'remote management'),
          },
          { id: 'file-sharing-not-advertised', value: !mentions(input.sharing, 'file sharing') },
        ]),
    ...(input.disabledServices === undefined
      ? []
      : [
          {
            id: 'remote-sharing-services-disabled',
            value: areRemoteServicesDisabled(input.disabledServices),
          },
        ]),
    ...(input.listeners === undefined
      ? []
      : [
          {
            id: 'common-remote-listeners-not-observed',
            value: !hasCommonRemoteListener(input.listeners),
          },
        ]),
  ];
}

/*** Match service labels only in transient command output and never include them in report evidence. */
function mentions(output: string, service: string): boolean {
  return output.toLowerCase().includes(service);
}

/*** Check system daemon disable metadata for the macOS services relevant to remote session exposure. */
function areRemoteServicesDisabled(output: string): boolean {
  return [
    'com.openssh.sshd',
    'com.apple.screensharing',
    'com.apple.remote.management',
    'com.apple.smbd',
  ].every((service) => new RegExp(`"${escapeRegExp(service)}"\\s*=>\\s*true`, 'i').test(output));
}

/*** Escape an internal fixed label before matching it in external command output. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

/*** Detect standard remote-access ports locally without emitting endpoints, process identities, or connection data. */
function hasCommonRemoteListener(output: string): boolean {
  return output.split(/\r?\n/u).some((line) => /\.(?:22|445|548|5900)\s/i.test(line));
}
