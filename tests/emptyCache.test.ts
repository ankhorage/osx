import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { realpath as canonicalPath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { emptyCacheAsync } from '../src/features/storage/adapters/outbound/emptyCacheAsync.js';
import { inspectTreeAsync } from '../src/features/storage/adapters/outbound/inspectTreeAsync.js';

test('empties only an unchanged inspected cache while preserving its root', async () => {
  const root = await mkdtemp(join(await canonicalPath(tmpdir()), 'osx-empty-'));
  try {
    const cache = join(root, 'cache');
    await mkdir(join(cache, 'nested'), { recursive: true });
    await writeFile(join(cache, 'nested', 'file'), 'cache');
    await writeFile(join(root, 'keep'), 'important');
    const before = await inspectTreeAsync(cache);
    if (!before.fingerprint) throw new Error('Inspection failed');
    await emptyCacheAsync(cache, before.fingerprint);
    expect(await readdir(cache)).toEqual([]);
    expect(await readFile(join(root, 'keep'), 'utf8')).toBe('important');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('refuses a symlink swap after the scan and leaves the target untouched', async () => {
  const root = await mkdtemp(join(await canonicalPath(tmpdir()), 'osx-swap-'));
  try {
    const cache = join(root, 'cache');
    const target = join(root, 'target');
    await mkdir(cache);
    await mkdir(target);
    await writeFile(join(cache, 'entry'), 'cache');
    await writeFile(join(target, 'keep'), 'important');
    const before = await inspectTreeAsync(cache);
    if (!before.fingerprint) throw new Error('Inspection failed');
    await rm(join(cache, 'entry'));
    await symlink(target, join(cache, 'entry'));
    await expect(emptyCacheAsync(cache, before.fingerprint)).rejects.toThrow();
    expect(await readFile(join(target, 'keep'), 'utf8')).toBe('important');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('aborts if an approved file becomes a link during execution', async () => {
  const root = await mkdtemp(join(await canonicalPath(tmpdir()), 'osx-race-'));
  try {
    const cache = join(root, 'cache');
    const target = join(root, 'target');
    await mkdir(cache);
    await mkdir(target);
    const file = join(cache, 'entry');
    await writeFile(file, 'cache');
    await writeFile(join(target, 'keep'), 'important');
    const before = await inspectTreeAsync(cache);
    if (!before.fingerprint) throw new Error('Inspection failed');
    await expect(
      emptyCacheAsync(cache, before.fingerprint, {
        beforeEntry: async () => {
          await rm(file);
          await symlink(target, file);
        },
      }),
    ).rejects.toThrow();
    expect(await readFile(join(target, 'keep'), 'utf8')).toBe('important');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
