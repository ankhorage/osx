import { expect, test } from 'bun:test';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { createOrphanedApplicationOperations } from '../src/features/storage/adapters/outbound/createOrphanedApplicationOperations.js';
import { readApplicationBundleIdAsync } from '../src/features/storage/adapters/outbound/readApplicationBundleIdAsync.js';
import { cleanStorageAsync } from '../src/features/storage/application/cleanStorageAsync.js';
import { scanOrphanedApplicationsAsync } from '../src/features/storage/application/scanOrphanedApplicationsAsync.js';
import type {
  OrphanedApplicationEvidenceSource,
  OrphanedApplicationHost,
} from '../src/types/orphanedApplications.js';
import type { StorageOperations } from '../src/types/storage.js';

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
      installedBundleIds: async () => evidence('applications', ['com.microsoft.VSCode']),
      receiptBundleIds: async () => evidence('package-receipts', ['vendor.match']),
      activeProcessNames: async () => evidence('active-processes', ['windsurf']),
      cliNames: async () => evidence('homebrew-apple-silicon', []),
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
      installedBundleIds: async () => evidence('applications', []),
      receiptBundleIds: async () => evidence('package-receipts', []),
      activeProcessNames: async () => evidence('active-processes', []),
      cliNames: async () => evidence('homebrew-apple-silicon', []),
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

test('uses unique path identities for same-app remnants so global cleanup can continue', async () => {
  const home = await realpath(await mkdtemp(join(tmpdir(), 'osx-orphans-')));
  try {
    await fixture(home, join('Library', 'Caches', 'com.example.App'), 'state', 'cache');
    await fixture(home, join('Library', 'Containers', 'com.example.App'), 'state', 'container');
    const orphanOperations = createOrphanedApplicationOperations(home, unavailableInventoryHost());
    const safeOperations: StorageOperations = {
      scan: async () => [
        {
          id: 'safe-cache',
          label: 'safe cache',
          estimatedBytes: 1,
          risk: 'safe',
          reason: 'fixture',
          fingerprint: 'fixture',
        },
      ],
      revalidate: async () => true,
      execute: async () => undefined,
      availableBytes: async () => 1,
    };
    const operations: StorageOperations = {
      scan: async () => [...(await safeOperations.scan()), ...(await orphanOperations.scan())],
      revalidate: async (candidate) => await safeOperations.revalidate(candidate),
      execute: async (candidate) => await safeOperations.execute(candidate),
      availableBytes: async () => await safeOperations.availableBytes(),
    };
    const candidates = (await orphanOperations.scan()).filter((candidate) =>
      candidate.path?.startsWith(home),
    );
    expect(candidates.map((candidate) => candidate.id)).toEqual([
      `orphaned-application:${join(home, 'Library', 'Caches', 'com.example.App')}`,
      `orphaned-application:${join(home, 'Library', 'Containers', 'com.example.App')}`,
    ]);
    const result = await cleanStorageAsync(operations, {
      select: async () => true,
      approve: async () => true,
    });
    expect(result.outcomes).toEqual([{ id: 'safe-cache', status: 'cleaned' }]);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test('unavailable evidence blocks an absent bundle from being described as uninstalled', async () => {
  const home = await realpath(await mkdtemp(join(tmpdir(), 'osx-orphans-')));
  try {
    await fixture(home, join('Library', 'Caches', 'com.example.App'), 'state', 'cache');
    const observations = (
      await scanOrphanedApplicationsAsync(home, unavailableInventoryHost())
    ).filter((observation) => observation.path.startsWith(home));
    expect(observations).toHaveLength(1);
    expect(observations[0]?.evidence).toContain('application ownership inventory is incomplete');
    expect(observations[0]?.blockers).toContain('spotlight evidence is unavailable');
    expect(observations[0]?.evidenceAvailability).toContainEqual({
      source: 'spotlight',
      available: false,
    });
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});

test.if(process.platform === 'darwin')(
  'reads binary application Info.plist bundle identifiers',
  async () => {
    const home = await realpath(await mkdtemp(join(tmpdir(), 'osx-orphans-')));
    try {
      const application = join(home, 'Example.app');
      const contents = join(application, 'Contents');
      const plist = join(contents, 'Info.plist');
      await mkdir(contents, { recursive: true });
      await writeFile(
        plist,
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.Binary</string></dict></plist>',
      );
      await promisify(execFile)('/usr/bin/plutil', ['-convert', 'binary1', '-o', plist, plist]);
      expect(await readApplicationBundleIdAsync(application)).toBe('com.example.Binary');
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  },
);

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

/** Return one successful evidence source for a fixture host. */
function evidence(
  source: string,
  values: readonly string[],
): readonly OrphanedApplicationEvidenceSource[] {
  return [{ source, available: true, values }];
}

/** Return an inventory that demonstrates incomplete evidence without losing ownership observations. */
function unavailableInventoryHost(): OrphanedApplicationHost {
  return {
    installedBundleIds: async () => [
      { source: 'applications', available: true, values: [] },
      { source: 'spotlight', available: false, values: [] },
    ],
    receiptBundleIds: async () => evidence('package-receipts', []),
    activeProcessNames: async () => evidence('active-processes', []),
    cliNames: async () => evidence('homebrew-apple-silicon', []),
    inspectPath: async () => ({ allocatedBytes: 1 }),
  };
}
