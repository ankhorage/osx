import { expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { realpath as canonicalPath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createBunCacheOperations } from '../src/features/storage/adapters/outbound/createBunCacheOperations.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import type { BunCacheHost } from '../src/types/bunCache.js';

/** Controlled fixture represents a macOS host without touching real caches. */
async function setup() {
  const home = await mkdtemp(join(await canonicalPath(tmpdir()), 'osx-bun-test-'));
  const cache = join(home, '.bun', 'install', 'cache');
  await mkdir(cache, { recursive: true });
  await writeFile(join(cache, 'package'), 'cached package');
  const host: BunCacheHost = {
    home,
    cwd: home,
    env: {},
    platform: 'darwin',
    currentPid: 123,
    listProcesses: async () => '123 /usr/local/bin/bun\n42 /usr/bin/other\n',
    freeBytes: async () => 100,
  };
  return { home, cache, host };
}

test('only an approved unchanged cache is emptied, leaving other user data intact', async () => {
  const { home, cache, host } = await setup();
  try {
    await writeFile(join(home, 'keep'), 'important');
    const operations = createBunCacheOperations(host);
    const candidate = (await operations.scan())[0];
    expect(candidate?.risk).toBe('safe');
    const result = await cleanStorageAsync(operations, {
      select: async () => {
        expect(await readFile(join(cache, 'package'), 'utf8')).toBe('cached package');
        return true;
      },
      approve: async () => {
        expect(await readFile(join(cache, 'package'), 'utf8')).toBe('cached package');
        return true;
      },
    });
    expect(result.outcomes[0]?.status).toBe('cleaned');
    expect(await readdir(cache)).toEqual([]);
    expect(await readFile(join(home, 'keep'), 'utf8')).toBe('important');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('rejected approval or dry-run does not change the cache', async () => {
  const { home, cache, host } = await setup();
  try {
    const operations = createBunCacheOperations(host);
    await cleanStorageAsync(operations, { select: async () => true, approve: async () => false });
    await cleanStorageAsync(
      operations,
      { select: async () => true, approve: async () => true },
      true,
    );
    expect(await readFile(join(cache, 'package'), 'utf8')).toBe('cached package');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('running Bun process and symlink swaps prevent cleanup', async () => {
  const { home, cache, host } = await setup();
  try {
    const busy = createBunCacheOperations({
      ...host,
      listProcesses: async () => '123 bun\n456 bun\n',
    });
    expect((await busy.scan())[0]?.risk).toBe('report-only');
    const operations = createBunCacheOperations(host);
    const result = await cleanStorageAsync(operations, {
      select: async () => true,
      approve: async () => {
        await rm(join(cache, 'package'));
        await symlink(join(home, 'keep'), join(cache, 'package'));
        return true;
      },
    });
    expect(result.outcomes[0]?.status).toBe('changed');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
