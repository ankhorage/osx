import { createBunCacheHost } from '../adapters/outbound/createBunCacheHost.js';
import { createBunCacheOperations } from '../adapters/outbound/createBunCacheOperations.js';

/*** Compose the host-backed Bun cache inspection and cleanup boundary. */
export function createDefaultBunCacheOperations(
  home: string,
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
) {
  return createBunCacheOperations(createBunCacheHost(home, cwd, env));
}
