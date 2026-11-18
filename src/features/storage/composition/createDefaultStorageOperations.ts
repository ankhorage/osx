import type { StorageCandidate, StorageOperations } from '../../../types/storage.js';
import { createBunCacheHost } from '../adapters/outbound/createBunCacheHost.js';
import { createBunCacheOperations } from '../adapters/outbound/createBunCacheOperations.js';
import { createToolCleanupOperations } from '../adapters/outbound/createToolCleanupOperations.js';
import { createToolCleanupDefinitions } from './createToolCleanupDefinitions.js';
import { scanStorageAsync } from './scanStorageAsync.js';

/*** Compose one inventory and dispatcher for report-only paths and safe tool adapters. */
export function createDefaultStorageOperations(
  home: string,
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
): StorageOperations {
  const toolOperations = createToolCleanupDefinitions().map(({ command, definition }) =>
    createToolCleanupOperations(command, definition),
  );
  const bun = createBunCacheOperations(createBunCacheHost(home, cwd, env));
  const sources = [bun, ...toolOperations];
  return {
    async scan() {
      const reported = await scanStorageAsync(home, sources);
      return reported;
    },
    async revalidate(candidate) {
      return await revalidateAsync(sources, candidate);
    },
    async execute(candidate) {
      await executeAsync(sources, candidate);
    },
    async availableBytes() {
      return await bun.availableBytes();
    },
  };
}

/*** Send a safe candidate only to the adapter that owns its stable identifier. */
async function revalidateAsync(
  sources: readonly StorageOperations[],
  candidate: StorageCandidate,
): Promise<boolean> {
  for (const source of sources) {
    const current = await source.scan();
    if (!current.some((item) => item.id === candidate.id)) continue;
    return await source.revalidate(candidate);
  }
  return false;
}

/*** Execute only through the adapter that advertises the approved candidate. */
async function executeAsync(
  sources: readonly StorageOperations[],
  candidate: StorageCandidate,
): Promise<void> {
  for (const source of sources) {
    const current = await source.scan();
    if (!current.some((item) => item.id === candidate.id)) continue;
    await source.execute(candidate);
    return;
  }
  throw new Error(`No cleanup adapter owns ${candidate.id}.`);
}
