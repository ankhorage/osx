import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { collectDefaultSecurityNetworkAsync } from '../../../features/security-network/composition/collectDefaultSecurityNetworkAsync.js';

/*** Render read-only local network posture evidence without probes, packet capture, or effectiveness claims. */
export async function diagnose(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (
    request.argv.length > 1 ||
    (request.argv[0] !== undefined && request.argv[0] !== '--json')
  ) {
    request.context.writeStderr('Usage: ankh osx network diagnose [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Network inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const evidence = await collectDefaultSecurityNetworkAsync();
  if (request.argv.includes('--json'))
    request.context.writeStdout(`${JSON.stringify(evidence, null, 2)}\n`);
  else request.context.writeStdout(renderDiagnosis(evidence));
  return { exitCode: 0 };
}

/*** Summarize measured configuration without treating it as a reachability or protection conclusion. */
function renderDiagnosis(
  evidence: Awaited<ReturnType<typeof collectDefaultSecurityNetworkAsync>>,
): string {
  return [
    `TCP listeners: loopback ${evidence.layer4.tcpLoopbackListenerCount}, non-loopback ${evidence.layer4.tcpNonLoopbackListenerCount} (${evidence.layer4.tcpListenersAvailability})`,
    `UDP bindings: loopback ${evidence.layer4.udpLoopbackBindingCount}, non-loopback ${evidence.layer4.udpNonLoopbackBindingCount} (${evidence.layer4.udpBindingsAvailability})`,
    `pf: ${evidence.packetFilter.status} (${evidence.packetFilter.statusAvailability})`,
    `Application Firewall: ${evidence.applicationFirewall.globalState} (${evidence.applicationFirewall.globalStateAvailability})`,
    `Limits: ${evidence.protectionLimitations.join(' ')}`,
  ].join('\n') + '\n';
}
