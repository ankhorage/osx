import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { collectDefaultSecurityNetworkAsync } from '../../../features/security-network/composition/collectDefaultSecurityNetworkAsync.js';

/*** Render passive local network configuration facts without exposing endpoint or identity values. */
export async function info(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (!hasOnlyJsonOption(request.argv)) {
    request.context.writeStderr('Usage: ankh osx network info [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Network inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const evidence = await collectDefaultSecurityNetworkAsync(new Set([3]));
  request.context.writeStdout(renderNetworkEvidence(evidence, request.argv.includes('--json')));
  return { exitCode: 0 };
}

/*** Render machine output or a concise availability-oriented summary without revealing raw host data. */
function renderNetworkEvidence(
  evidence: Awaited<ReturnType<typeof collectDefaultSecurityNetworkAsync>>,
  json: boolean,
): string {
  if (json)
    return `${JSON.stringify(
      { collectedAt: evidence.collectedAt, layer3: evidence.layer3 },
      null,
      2,
    )}\n`;
  return [
    `Interfaces: ${evidence.layer3.interfaceCount} (${evidence.layer3.interfacesAvailability})`,
    `DNS resolvers: ${evidence.layer3.dnsResolverCount} (${evidence.layer3.dnsAvailability})`,
    `VPN services: ${evidence.layer3.vpnServiceCount} (${evidence.layer3.vpnServicesAvailability})`,
    `Network extensions: ${evidence.layer3.networkExtensionCount} (${evidence.layer3.networkExtensionsAvailability})`,
    `Proxy: HTTP ${evidence.layer3.webProxy}, HTTPS ${evidence.layer3.secureWebProxy} (${evidence.layer3.proxyAvailability})`,
  ].join('\n') + '\n';
}

/*** Accept one optional machine-output flag while rejecting ambiguous command input. */
function hasOnlyJsonOption(argv: readonly string[]): boolean {
  return argv.length === 0 || (argv.length === 1 && argv[0] === '--json');
}
