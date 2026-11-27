import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inventoryInodesAsync } from '../src/features/storage/application/inventoryInodesAsync.js';

test('counts entries and inode identities without following symlinks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'osx-inodes-'));
  try {
    await mkdir(join(root, 'nested'));
    await writeFile(join(root, 'nested', 'file'), 'value');
    await symlink(join(root, 'nested'), join(root, 'linked'));
    const inventory = await inventoryInodesAsync(root, 5);
    expect(inventory.files).toBe(1);
    expect(inventory.directories).toBe(2);
    expect(inventory.symlinks).toBe(1);
    expect(inventory.entries).toBe(4);
    expect(inventory.distinctInodes).toBe(4);
    expect(inventory.topSubtrees).toEqual([
      { path: join(root, 'nested'), entries: 2 },
      { path: join(root, 'linked'), entries: 1 },
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
