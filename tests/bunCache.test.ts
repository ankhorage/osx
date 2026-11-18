import { expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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

test('reports the Bun cache but keeps native deletion disabled until issue #6', async () => {
  const { home, cache, host } = await setup();
  try {
    const operations = createBunCacheOperations(host);
    const candidate = (await operations.scan())[0];
    expect(candidate?.risk).toBe('report-only');
    const result = await cleanStorageAsync(operations, {
      select: async () => true,
      approve: async () => true,
    });
    expect(result.selected).toEqual([]);
    expect(await readFile(join(cache, 'package'), 'utf8')).toBe('cached package');
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

test('Bun process availability remains visible in the report-only reason', async () => {
  const { home, cache, host } = await setup();
  try {
    const busy = createBunCacheOperations({
      ...host,
      listProcesses: async () => '123 bun\n456 bun\n',
    });
    expect((await busy.scan())[0]?.risk).toBe('report-only');
    expect((await busy.scan())[0]?.reason).toContain('another Bun process is running');
    expect(await readFile(join(cache, 'package'), 'utf8')).toBe('cached package');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
