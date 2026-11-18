import type { SecurityNetworkHost } from '../../ports/securityNetworkHost.js';
import { executeSecurityNetworkCommandAsync } from './executeSecurityNetworkCommandAsync.js';

/*** Create the macOS read-only process adapter used by the network-security collector. */
export function createSecurityNetworkHost(): SecurityNetworkHost {
  return {
    executeAsync: executeSecurityNetworkCommandAsync,
    now: () => new Date().toISOString(),
  };
}
