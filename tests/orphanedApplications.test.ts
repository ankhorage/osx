import { expect, test } from 'bun:test';
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createOrphanedApplicationOperations } from '../src/features/storage/adapters/outbound/createOrphanedApplicationOperations.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import { scanOrphanedApplicationsAsync } from '../src/features/storage/application/scanOrphanedApplicationsAsync.js';
import type { OrphanedApplicationHost } from '../src/types/orphanedApplications.js';

test('reports manifest-backed remnants while protecting installed, shared, active, and ambiguous data', async () => {
  const home = await realpath(await mkdtemp(join(tmpdir(), 'osx-orphans-')));
  try {
    await fixture(home, '.cursor', 'product.json', '{"bundleId":"com.cursor.Cursor"}');
    await fixture(home, '.windsurf', 'product.json', '{"bundleId":"com.windsurf.Windsurf"}');
    await fixture(
      home,
      join('Library', 'Containers', 'com.microsoft.VSCode'),
      'state',
      'installed',
    );
    await fixture(
      home,
      join('Library', 'Group Containers', 'group.com.microsoft.office'),
      'state',
      'shared',
    );
    await fixture(
      home,
      join('Library', 'Application Support', 'vendor.match'),
      'state',
      'receipt only',
    );
    await mkdir(join(home, '.unknown'), { recursive: true });
    await symlink(join(home, '.cursor'), join(home, 'Library', 'Containers', 'com.example.Linked'));
    const host: OrphanedApplicationHost = {
      installedBundleIds: async () => ['com.microsoft.VSCode'],
      receiptBundleIds: async () => ['vendor.match'],
      activeProcessNames: async () => ['windsurf'],
      cliNames: async () => [],
      inspectPath: async () => ({ allocatedBytes: 1 }),
    };
    const observations = await scanOrphanedApplicationsAsync(home, host);
    const userObservations = observations.filter((item) => item.path.startsWith(home));
    expect(userObservations.map((item) => item.bundleId)).toEqual([
      'com.cursor.Cursor',
      'com.windsurf.Windsurf',
      'vendor.match',
      'com.microsoft.VSCode',
      'group.com.microsoft.office',
    ]);
    expect(
      userObservations.find((item) => item.bundleId === 'com.microsoft.VSCode')?.blockers,
    ).toContain('application bundle is installed');
    expect(
      userObservations.find((item) => item.bundleId === 'com.windsurf.Windsurf')?.blockers,
    ).toContain('matching process is active');
    expect(
      userObservations.find((item) => item.bundleId === 'group.com.microsoft.office')?.blockers,
    ).toContain('shared group container');
    expect(userObservations.find((item) => item.bundleId === 'vendor.match')?.blockers).toContain(
      'package receipt exists',
    );
    expect(userObservations.some((item) => item.path.endsWith('.unknown'))).toBe(false);
    expect(userObservations.some((item) => item.path.endsWith('com.example.Linked'))).toBe(false);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('orphan operations remain report-only and the approval engine cannot execute them', async () => {
  const home = await realpath(await mkdtemp(join(tmpdir(), 'osx-orphans-')));
  try {
    await fixture(home, '.cursor', 'product.json', '{"bundleId":"com.cursor.Cursor"}');
    const operations = createOrphanedApplicationOperations(home, {
      installedBundleIds: async () => [],
      receiptBundleIds: async () => [],
      activeProcessNames: async () => [],
      cliNames: async () => [],
      inspectPath: async () => ({ allocatedBytes: 1 }),
    });
    const result = await cleanStorageAsync(operations, {
      select: async () => {
        throw new Error('report-only candidates must not be selected');
      },
      approve: async () => {
        throw new Error('report-only candidates must not be approved');
      },
    });
    expect((await operations.scan()).every((item) => item.risk === 'report-only')).toBe(true);
    expect(result.selected).toEqual([]);
    expect(result.outcomes).toEqual([]);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

/** Create one app-data fixture beneath the requested user-owned path. */
async function fixture(
  home: string,
  directory: string,
  filename: string,
  content: string,
): Promise<void> {
  const path = join(home, directory);
  await mkdir(path, { recursive: true });
  await writeFile(join(path, filename), content);
}
