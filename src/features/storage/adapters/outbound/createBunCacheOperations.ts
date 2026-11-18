import { lstat, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';

import type { BunCacheHost } from '../../../../types/bunCache.js';
import type { StorageCandidate, StorageOperations } from '../../../../types/storage.js';
import { inspectTreeAsync } from './inspectTreeAsync.js';
import { resolveBunCacheAsync } from './resolveBunCacheAsync.js';

/*** Report the Bun cache without enabling the deferred native mutation adapter. */
export function createBunCacheOperations(host: BunCacheHost): StorageOperations {
  return {
    async scan() {
      return [await inspectBunCacheAsync(host)];
    },
    async revalidate() {
      return await Promise.resolve(false);
    },
    async execute() {
      await Promise.resolve();
      throw new Error('Direct Bun cache deletion is deferred to issue #6.');
    },
    async availableBytes() {
      return await host.freeBytes(host.home);
    },
  };
}

/*** Reject missing, unsafe, differently mounted or actively used cache trees. */
async function inspectBunCacheAsync(host: BunCacheHost): Promise<StorageCandidate> {
  const selection = await resolveBunCacheAsync(host.home, host.cwd, host.env);
  const base = { id: 'bun-cache', label: 'Bun package cache' };
  if (!selection.path)
    return {
      ...base,
      estimatedBytes: null,
      risk: 'report-only',
      reason: selection.reason,
      fingerprint: '',
    };
  const { path } = selection;
  const inspection = await inspectTreeAsync(path, { requireWritable: true });
  const preflight = await preflightAsync(host, path);
  const reason = inspection.blockers.join(', ') || preflight;
  return {
    ...base,
    path,
    estimatedBytes: inspection.allocatedBytes,
    risk: 'report-only',
    reason: reason || 'Direct Bun cache deletion is deferred to issue #6',
    fingerprint: inspection.fingerprint ?? '',
  };
}

/*** Verify canonical ownership boundaries, filesystem accounting and process availability. */
async function preflightAsync(host: BunCacheHost, path: string): Promise<string> {
  if (host.platform !== 'darwin') return 'macOS required';
  try {
    if ((await realpath(host.home)) !== resolve(host.home)) return 'home path is not canonical';
    const [home, cache] = await Promise.all([
      lstat(host.home, { bigint: true }),
      lstat(path, { bigint: true }),
    ]);
    if (home.dev !== cache.dev) return 'cache is on a different filesystem';
    const processes = await host.listProcesses();
    if (!processes.trim()) return 'process inventory unavailable';
    for (const line of processes.trim().split('\n')) {
      const match = /^\s*(\d+)\s+(.+?)\s*$/u.exec(line);
      if (!match) return 'process inventory is invalid';
      const name = match[2]?.split('/').pop();
      if (Number(match[1]) !== host.currentPid && name === 'bun')
        return 'another Bun process is running';
    }
    return '';
  } catch {
    return 'cache preflight unavailable';
  }
}
