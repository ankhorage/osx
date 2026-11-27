import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { listDefaultApfsSnapshotsAsync } from '../../../../features/backup/composition/listDefaultApfsSnapshotsAsync.js';

/*** Render aggregate APFS snapshots for a selected volume or the standard boot volumes without mutating the host. */
export async function list(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  const json = request.argv.includes('--json');
  const volumes = request.argv.filter((argument) => argument !== '--json');
  if (
    request.argv.length > 2 ||
    request.argv.filter((argument) => argument === '--json').length > 1 ||
    volumes.length > 1
  ) {
    request.context.writeStderr('Usage: ankh osx backup snapshots list [volume] [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('APFS snapshot inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const snapshots = await listDefaultApfsSnapshotsAsync(
    volumes.length === 1 ? volumes : ['/', '/System/Volumes/Data'],
  );
  request.context.writeStdout(
    json ? `${JSON.stringify({ snapshots }, null, 2)}\n` : renderSnapshotSummary(snapshots),
  );
  return { exitCode: 0 };
}

/*** Render a redacted, human-readable snapshot inventory without exposing snapshot names. */
function renderSnapshotSummary(
  snapshots: Awaited<ReturnType<typeof listDefaultApfsSnapshotsAsync>>,
): string {
  return snapshots
    .map(
      (snapshot) =>
        `${snapshot.volume}: ${snapshot.snapshotCount} ${snapshot.kind} snapshots (${snapshot.availability})`,
    )
    .join('\n')
    .concat('\n');
}
