import type { SecurityNetworkEvidence } from '../../../types/securityNetwork.js';
import { createLayer3Evidence } from '../domain/createLayer3Evidence.js';
import { createLayer4Evidence } from '../domain/createLayer4Evidence.js';
import type { SecurityNetworkHost } from '../ports/securityNetworkHost.js';
import { collectLayer3CommandResultsAsync } from './collectLayer3CommandResultsAsync.js';
import { collectLayer4CommandResultsAsync } from './collectLayer4CommandResultsAsync.js';

/*** Collect passive macOS Layer 3 and 4 evidence without scans, privilege escalation, or sensitive output. */
export async function collectSecurityNetworkAsync(
  host: SecurityNetworkHost,
): Promise<SecurityNetworkEvidence> {
  const [layer3Results, layer4Results] = await Promise.all([
    collectLayer3CommandResultsAsync(host),
    collectLayer4CommandResultsAsync(host),
  ]);

  return {
    collectedAt: host.now(),
    ...createLayer3Evidence(...layer3Results),
    ...createLayer4Evidence(...layer4Results),
    protectionLimitations: [
      'Observed configuration and bindings do not establish that traffic is blocked or allowed.',
      'pf packet filtering and Apple Application Firewall are separate controls with different scope.',
      'QUIC remains unknown without protocol-specific local evidence.',
    ],
  };
}
