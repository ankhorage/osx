import { expect, test } from 'bun:test';

import { collectBackupStatusAsync } from '../src/features/backup/application/collectBackupStatusAsync.js';
import { listApfsSnapshotsAsync } from '../src/features/backup/application/listApfsSnapshotsAsync.js';
import type { BackupHost } from '../src/features/backup/ports/backupHost.js';

test('reports Time Machine metadata without retaining destination or backup path values', async () => {
  const report = await collectBackupStatusAsync(
    host({
      'tmutil status': 'Running = 0;',
      'tmutil destinationinfo': 'Name : Private Backup\nEncrypted : Yes\n',
      'tmutil latestbackup': '/Volumes/Private Backup/2026-11-26-120000',
    }),
  );
  expect(report).toMatchObject({
    destinationEncrypted: true,
    lastBackupObserved: true,
    restoreReadiness: 'unknown',
  });
  expect(JSON.stringify(report)).not.toContain('Private Backup');
});

test('counts system and Data snapshots without retaining snapshot names', async () => {
  const snapshots = await listApfsSnapshotsAsync(
    host({
      'diskutil apfs listsnapshots /':
        'Snapshot UUID: private-system\nSnapshot UUID: private-system-two',
      'diskutil apfs listsnapshots /System/Volumes/Data':
        'Snapshot UUID: private-data\nSnapshot Name: private-data\nSnapshot XID: 9',
    }),
    ['/', '/System/Volumes/Data'],
  );
  expect(snapshots).toEqual([
    { volume: '/', kind: 'system', availability: 'available', snapshotCount: 2 },
    { volume: '/System/Volumes/Data', kind: 'data', availability: 'available', snapshotCount: 1 },
  ]);
});

/** Create a deterministic host fixture that executes no local command. */
function host(values: Readonly<Record<string, string>>): BackupHost {
  return {
    executeAsync: async (command) => ({
      availability: 'available',
      stdout: values[command.join(' ')] ?? '',
    }),
    now: () => '2026-11-26T00:00:00.000Z',
  };
}
