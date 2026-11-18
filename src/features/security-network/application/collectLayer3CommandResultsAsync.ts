import type {
  SecurityNetworkCommandResult,
  SecurityNetworkHost,
} from '../ports/securityNetworkHost.js';

/** Collect the fixed passive local commands needed for Layer 3 and pf evidence. */
export async function collectLayer3CommandResultsAsync(
  host: SecurityNetworkHost,
): Promise<
  readonly [
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
  ]
> {
  return Promise.all([
    host.executeAsync(['ifconfig', '-a']),
    host.executeAsync(['netstat', '-rn', '-f', 'inet']),
    host.executeAsync(['netstat', '-rn', '-f', 'inet6']),
    host.executeAsync(['sysctl', '-n', 'net.inet.ip.forwarding']),
    host.executeAsync(['sysctl', '-n', 'net.inet6.ip6.forwarding']),
    host.executeAsync(['scutil', '--nc', 'list']),
    host.executeAsync(['systemextensionsctl', 'list']),
    host.executeAsync(['pfctl', '-s', 'info']),
    host.executeAsync(['pfctl', '-sr']),
    host.executeAsync(['pfctl', '-s', 'Anchors']),
  ]);
}
