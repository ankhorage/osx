import type {
  SecurityNetworkCommandResult,
  SecurityNetworkHost,
} from '../ports/securityNetworkHost.js';

/** Collect the fixed passive local commands needed for Layer 4 and ALF evidence. */
export async function collectLayer4CommandResultsAsync(
  host: SecurityNetworkHost,
): Promise<
  readonly [
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
  ]
> {
  return Promise.all([
    host.executeAsync(['lsof', '-nP', '-iTCP', '-sTCP:LISTEN']),
    host.executeAsync(['lsof', '-nP', '-iUDP']),
    host.executeAsync(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate']),
    host.executeAsync(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getstealthmode']),
  ]);
}
