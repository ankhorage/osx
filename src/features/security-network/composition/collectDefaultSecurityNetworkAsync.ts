import type { SecurityNetworkEvidence } from '../../../types/securityNetwork.js';
import { createSecurityNetworkHost } from '../adapters/outbound/createSecurityNetworkHost.js';
import { collectSecurityNetworkAsync } from '../application/collectSecurityNetworkAsync.js';

/*** Collect the default passive macOS Layer 3 and 4 evidence through the local process adapter. */
export async function collectDefaultSecurityNetworkAsync(): Promise<SecurityNetworkEvidence> {
  return collectSecurityNetworkAsync(createSecurityNetworkHost());
}
