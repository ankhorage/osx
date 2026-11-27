import type {
  SecurityNetworkCommandResult,
  SecurityNetworkHost,
} from '../ports/securityNetworkHost.js';

/** Collect the fixed passive local commands needed for Layer 3 and pf evidence. */
export async function collectLayer3CommandResultsAsync(
  host: SecurityNetworkHost,
  input: { readonly signal?: AbortSignal } = {},
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
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
  ]
> {
  return Promise.all([
    host.executeAsync(['ifconfig', '-a'], input),
    host.executeAsync(['netstat', '-rn', '-f', 'inet'], input),
    host.executeAsync(['netstat', '-rn', '-f', 'inet6'], input),
    host.executeAsync(['sysctl', '-n', 'net.inet.ip.forwarding'], input),
    host.executeAsync(['sysctl', '-n', 'net.inet6.ip6.forwarding'], input),
    host.executeAsync(['scutil', '--dns'], input),
    host.executeAsync(['scutil', '--proxy'], input),
    host.executeAsync(['scutil', '--nc', 'list'], input),
    host.executeAsync(['systemextensionsctl', 'list'], input),
    host.executeAsync(['pfctl', '-s', 'info'], input),
    host.executeAsync(['pfctl', '-sr'], input),
    host.executeAsync(['pfctl', '-s', 'Anchors'], input),
  ]);
}
