import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withCacheLockAsync } from '../src/features/storage/adapters/outbound/withCacheLockAsync.js';

test('a second cleanup cannot run while the first holds the cache lock', async () => {
  const root = await mkdtemp(join(tmpdir(), 'osx-lock-'));
  try {
    const cache = join(root, 'cache');
    await mkdir(cache);
    let release!: () => void;
    let ready!: () => void;
    const started = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const first = withCacheLockAsync(cache, async () => {
      ready();
      await gate;
    });
    await started;
    let secondRan = false;
    await expect(
      withCacheLockAsync(cache, async () => {
        secondRan = true;
      }),
    ).rejects.toThrow();
    expect(secondRan).toBe(false);
    release();
    await first;
    await expect(withCacheLockAsync(cache, async () => 'ok')).resolves.toBe('ok');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
