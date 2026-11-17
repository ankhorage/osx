import { realpath } from 'node:fs/promises';

import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { scanStorageAsync } from '../../../features/storage/composition/scanStorageAsync.js';

/*** Render the storage inventory without mutating the host. */
export async function scan(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (
    request.argv.some((arg) => arg !== '--json') ||
    request.argv.filter((arg) => arg === '--json').length > 1
  ) {
    request.context.writeStderr('Usage: ankh osx storage scan [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Storage inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const home = request.context.env.HOME;
  if (!home) {
    request.context.writeStderr('HOME is unavailable; refusing to inspect storage.\n');
    return { exitCode: 1 };
  }
  try {
    const candidates = await scanStorageAsync(await realpath(home), {
      cwd: request.context.cwd,
      env: request.context.env,
    });
    if (request.argv.includes('--json')) {
      request.context.writeStdout(`${JSON.stringify({ candidates }, null, 2)}\n`);
    } else {
      for (const item of candidates) {
        request.context.writeStdout(
          `${item.label} (${item.path ?? 'location unavailable'}): ${item.estimatedBytes === null ? 'unknown size' : `${item.estimatedBytes} allocated bytes`} [${item.risk}] ${item.reason}\n`,
        );
      }
    }
    return { exitCode: 0 };
  } catch (error) {
    request.context.writeStderr(
      `Storage scan failed: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return { exitCode: 1 };
  }
}
