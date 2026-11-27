import type { SecurityNetworkEvidence } from '../../../types/securityNetwork.js';
import { createLayer3Evidence } from '../domain/createLayer3Evidence.js';
import { createLayer4Evidence } from '../domain/createLayer4Evidence.js';
import type { SecurityNetworkHost } from '../ports/securityNetworkHost.js';
import { collectLayer3CommandResultsAsync } from './collectLayer3CommandResultsAsync.js';
import { collectLayer4CommandResultsAsync } from './collectLayer4CommandResultsAsync.js';

/*** Collect passive macOS Layer 3 and 4 evidence without scans, privilege escalation, or sensitive output. */
export async function collectSecurityNetworkAsync(
  host: SecurityNetworkHost,
  layers: ReadonlySet<3 | 4> = new Set([3, 4]),
  input: { readonly signal?: AbortSignal } = {},
): Promise<SecurityNetworkEvidence> {
  const layer3Results = layers.has(3)
    ? await collectLayer3CommandResultsAsync(host, input)
    : unavailableLayer3Results();
  const layer4Results = layers.has(4)
    ? await collectLayer4CommandResultsAsync(host, input)
    : unavailableLayer4Results();

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

/** Represent deliberately unrequested sources as unavailable without executing their commands. */
function unavailableLayer3Results(): Awaited<ReturnType<typeof collectLayer3CommandResultsAsync>> {
  return [
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
    unavailableResult(),
  ];
}

/** Represent deliberately unrequested sources as unavailable without executing their commands. */
function unavailableLayer4Results(): Awaited<ReturnType<typeof collectLayer4CommandResultsAsync>> {
  return [unavailableResult(), unavailableResult(), unavailableResult(), unavailableResult()];
}

/** Use one explicit unavailable result for each deliberately unrequested source. */
function unavailableResult() {
  return { exitCode: null, stdout: '', status: 'unsupported' as const };
}
