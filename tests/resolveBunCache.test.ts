import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveBunCacheAsync } from '../src/features/storage/adapters/outbound/resolveBunCacheAsync.js';

test('resolves the default cache and rejects unsafe overrides or unknown configuration', async () => {
  const home = await mkdtemp(join(tmpdir(), 'osx-bun-config-'));
  try {
    const cwd = join(home, 'project');
    await mkdir(cwd);
    expect((await resolveBunCacheAsync(home, cwd, {})).path).toBe(join(home, '.bun/install/cache'));
    expect(
      (await resolveBunCacheAsync(home, cwd, { BUN_INSTALL_CACHE_DIR: join(home, 'Documents') }))
        .path,
    ).toBeNull();
    expect(
      (
        await resolveBunCacheAsync(home, cwd, {
          BUN_INSTALL_CACHE_DIR: join(home, '.cache/bun/custom'),
        })
      ).path,
    ).toBe(join(home, '.cache/bun/custom'));
    await writeFile(join(cwd, 'bunfig.toml'), '[install.cache]\ndir = "elsewhere"\n');
    expect((await resolveBunCacheAsync(home, cwd, {})).path).toBeNull();
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
