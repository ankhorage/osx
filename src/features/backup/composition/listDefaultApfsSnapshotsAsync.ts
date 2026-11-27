import type { ApfsSnapshotEvidence } from '../../../types/backup.js';
import { listApfsSnapshotsAsync } from '../application/listApfsSnapshotsAsync.js';
import { createMacosBackupHost } from '../adapters/outbound/createMacosBackupHost.js';

/*** List aggregate snapshots for selected volumes without retaining snapshot identities. */
export function listDefaultApfsSnapshotsAsync(
  volumes: readonly string[],
): Promise<readonly ApfsSnapshotEvidence[]> {
  return listApfsSnapshotsAsync(createMacosBackupHost(), volumes);
}
