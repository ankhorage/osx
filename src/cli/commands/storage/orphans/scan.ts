import { realpath } from 'node:fs/promises';

import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { scanOrphanedApplicationStorageAsync } from '../../../../features/storage/composition/createOrphanedApplicationStorageOperations.js';

/** Render the read-only, report-only inventory of potentially orphaned application data. */
export async function scan(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 1 || request.argv.some((argument) => argument !== '--json')) {
    request.context.writeStderr('Usage: ankh osx storage orphans scan [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Orphan inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  if (!request.context.env.HOME) {
    request.context.writeStderr('HOME is unavailable; refusing to inspect application remnants.\n');
    return { exitCode: 1 };
  }
  try {
    const home = await realpath(request.context.env.HOME);
    const applications = await scanOrphanedApplicationStorageAsync(home);
    if (request.argv.includes('--json')) {
      request.context.writeStdout(`${JSON.stringify({ applications }, null, 2)}\n`);
    } else {
      for (const application of applications) {
        request.context.writeStdout(
          `${application.label} (${application.path}): ${application.allocatedBytes} allocated bytes [${application.confidence}; report-only] ${[...application.evidence, ...application.blockers].join('; ')}\n`,
        );
      }
    }
    return { exitCode: 0 };
  } catch (error) {
    request.context.writeStderr(
      `Orphan inspection failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return { exitCode: 1 };
  }
}
