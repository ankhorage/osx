import type {
  SecurityNetworkCommandResult,
  SecurityNetworkHost,
} from '../ports/securityNetworkHost.js';

/** Collect the fixed passive local commands needed for Layer 4 and ALF evidence. */
export async function collectLayer4CommandResultsAsync(
  host: SecurityNetworkHost,
  input: { readonly signal?: AbortSignal } = {},
): Promise<
  readonly [
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
    SecurityNetworkCommandResult,
  ]
> {
  return Promise.all([
    host.executeAsync(['lsof', '-nP', '-iTCP', '-sTCP:LISTEN'], input),
    host.executeAsync(['lsof', '-nP', '-iUDP'], input),
    host.executeAsync(
      ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
      input,
    ),
    host.executeAsync(
      ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getstealthmode'],
      input,
    ),
  ]);
}
