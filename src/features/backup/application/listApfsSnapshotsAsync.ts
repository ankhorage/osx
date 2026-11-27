import type { ApfsSnapshotEvidence } from '../../../types/backup.js';
import type { BackupHost } from '../ports/backupHost.js';

/*** List only aggregate snapshot counts for explicitly supplied APFS volumes. */
export async function listApfsSnapshotsAsync(
  host: BackupHost,
  volumes: readonly string[],
): Promise<readonly ApfsSnapshotEvidence[]> {
  return Promise.all(
    volumes.map(async (volume) =>
      toEvidence(volume, await host.executeAsync(['diskutil', 'apfs', 'listsnapshots', volume])),
    ),
  );
}

/*** Redact snapshot names while preserving volume role, availability, and aggregate inventory count. */
function toEvidence(
  volume: string,
  result: Awaited<ReturnType<BackupHost['executeAsync']>>,
): ApfsSnapshotEvidence {
  return {
    volume,
    kind: snapshotVolumeKind(volume),
    availability: result.availability,
    snapshotCount: result.availability === 'available' ? countSnapshots(result.stdout) : 'unknown',
  };
}

/*** Classify standard APFS Data-volume paths and user-visible ` - Data` volume names. */
function snapshotVolumeKind(volume: string): ApfsSnapshotEvidence['kind'] {
  if (volume === '/') return 'system';
  return /(^|\/)Data$|\s-\sData$/i.test(volume) ? 'data' : 'other';
}

/*** Count one documented UUID header per snapshot entry without retaining identifying metadata. */
function countSnapshots(output: string): number {
  return output.split('\n').filter((line) => /^\s*Snapshot UUID\s*:/i.test(line)).length;
}
