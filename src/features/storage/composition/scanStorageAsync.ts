import { join } from 'node:path';

import type { StorageCandidate, StorageOperations } from '../../../types/storage.js';
import { inspectTreeAsync } from '../adapters/outbound/inspectTreeAsync.js';

/*** Inspect known user-owned cache and high-risk paths without changing them. */
export async function scanStorageAsync(
  home: string,
  operations: readonly StorageOperations[] = [],
): Promise<readonly StorageCandidate[]> {
  const definitions = storagePaths(home);
  const inspections = await Promise.all(
    definitions.map(async (definition) => ({
      definition,
      inspection: await inspectTreeAsync(definition.path),
    })),
  );
  const adapterCandidates = (
    await Promise.all(operations.map(async (operation) => await operation.scan()))
  ).flat();
  return [
    ...adapterCandidates,
    ...inspections.map(({ definition, inspection }) => ({
      id: definition.id,
      label: definition.label,
      path: definition.path,
      estimatedBytes: inspection.allocatedBytes,
      risk: 'report-only' as const,
      reason:
        inspection.blockers.length > 0
          ? inspection.blockers.join(', ')
          : 'Cleanup adapter not yet verified',
      fingerprint: inspection.fingerprint ?? '',
    })),
  ];
}

/*** Define independent user-owned paths; none is an ancestor of another. */
function storagePaths(home: string) {
  return [
    { id: 'npm-cache', label: 'npm package cache', path: join(home, '.npm', '_cacache') },
    { id: 'gradle-cache', label: 'Gradle cache', path: join(home, '.gradle', 'caches') },
    {
      id: 'playwright-cache',
      label: 'Playwright browsers',
      path: join(home, 'Library', 'Caches', 'ms-playwright'),
    },
    {
      id: 'xcode-derived-data',
      label: 'Xcode DerivedData',
      path: join(home, 'Library', 'Developer', 'Xcode', 'DerivedData'),
    },
    {
      id: 'xcode-archives',
      label: 'Xcode archives',
      path: join(home, 'Library', 'Developer', 'Xcode', 'Archives'),
    },
    {
      id: 'device-backups',
      label: 'iOS device backups',
      path: join(home, 'Library', 'Application Support', 'MobileSync', 'Backup'),
    },
    { id: 'mail', label: 'Mail data', path: join(home, 'Library', 'Mail') },
    { id: 'messages', label: 'Messages data', path: join(home, 'Library', 'Messages') },
    {
      id: 'docker-disk',
      label: 'Docker virtual disk',
      path: join(
        home,
        'Library',
        'Containers',
        'com.docker.docker',
        'Data',
        'vms',
        '0',
        'data',
        'Docker.raw',
      ),
    },
    { id: 'downloads', label: 'Downloads', path: join(home, 'Downloads') },
  ];
}
