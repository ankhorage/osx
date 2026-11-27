import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { collectDefaultBackupStatusAsync } from '../../../features/backup/composition/collectDefaultBackupStatusAsync.js';

/*** Render a read-only Time Machine status report without exposing destination identities. */
export async function status(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || (request.argv.length === 1 && request.argv[0] !== '--json')) {
    request.context.writeStderr('Usage: ankh osx backup status [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Backup inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const report = await collectDefaultBackupStatusAsync();
  request.context.writeStdout(`${JSON.stringify(report, null, 2)}\n`);
  return { exitCode: 0 };
}
