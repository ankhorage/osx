import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { collectMacosApfsAsync } from '../../../features/storage/adapters/outbound/collectMacosApfsAsync.js';

/*** Render raw documented APFS and live inode-accounting observations without interpreting snapshots. */
export async function apfs(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || (request.argv.length === 1 && request.argv[0] !== '--json')) {
    request.context.writeStderr('Usage: ankh osx storage apfs [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('APFS inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const diagnostics = await collectMacosApfsAsync();
  request.context.writeStdout(request.argv.includes('--json') ? `${JSON.stringify(diagnostics, null, 2)}\n` : `${diagnostics.apfs.status}; live inode accounting: ${diagnostics.inodeAccounting.status}; available bytes: ${diagnostics.capacity.availableBytes ?? 'unknown'}\n`);
  return { exitCode: 0 };
}
