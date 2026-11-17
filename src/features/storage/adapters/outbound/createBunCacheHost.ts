import { execFile } from 'node:child_process';
import { statfs } from 'node:fs/promises';
import { promisify } from 'node:util';

import type { BunCacheHost } from '../../../../types/bunCache.js';

/*** Supply read-only process and filesystem inspection for Bun cache cleanup. */
export function createBunCacheHost(
  home: string,
  cwd: string,
  env: Readonly<Record<string, string | undefined>>,
): BunCacheHost {
  return {
    home,
    cwd,
    env,
    platform: process.platform,
    currentPid: process.pid,
    async listProcesses() {
      const result = await promisify(execFile)('/bin/ps', ['-axo', 'pid=,comm='], {
        timeout: 10_000,
        maxBuffer: 2_000_000,
      });
      return result.stdout;
    },
    async freeBytes(path) {
      try {
        const stats = await statfs(path, { bigint: true });
        const bytes = stats.bavail * stats.bsize;
        return bytes <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(bytes) : null;
      } catch {
        return null;
      }
    },
  };
}
