import { realpath } from 'node:fs/promises';

import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { cleanStorageAsync } from '../../../../features/storage/application/cleanStorageAsync.js';
import { createOrphanedApplicationStorageOperations } from '../../../../features/storage/composition/createOrphanedApplicationStorageOperations.js';

/** Run the shared approval engine while preserving orphaned applications as report-only. */
export async function clean(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || request.argv.some((argument) => argument !== '--dry-run')) {
    request.context.writeStderr('Usage: ankh osx storage orphans clean [--dry-run]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Orphan cleanup is available only on macOS.\n');
    return { exitCode: 1 };
  }
  if (!request.context.env.HOME) {
    request.context.writeStderr('HOME is unavailable.\n');
    return { exitCode: 1 };
  }
  try {
    const home = await realpath(request.context.env.HOME);
    const operations = createOrphanedApplicationStorageOperations(home);
    const result = await cleanStorageAsync(
      operations,
      { select: () => Promise.resolve(false), approve: () => Promise.resolve(false) },
      request.argv.includes('--dry-run'),
    );
    request.context.writeStdout(
      result.selected.length === 0
        ? 'No eligible application remnants: all observations remain report-only until a safe Trash adapter is available.\n'
        : 'Cleanup cancelled.\n',
    );
    return { exitCode: 0 };
  } catch (error) {
    request.context.writeStderr(
      `Orphan cleanup failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return { exitCode: 1 };
  }
}
