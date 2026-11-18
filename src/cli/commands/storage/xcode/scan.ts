import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { scanXcodeRuntimesAsync } from '../../../../features/xcode-runtimes/composition/scanXcodeRuntimesAsync.js';

/*** Render the Xcode Simulator runtime inventory without mutating the host. */
export async function scan(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  if (request.argv.length > 0 && (request.argv.length !== 1 || request.argv[0] !== '--json')) {
    request.context.writeStderr('Usage: ankh osx storage xcode scan [--json]\n');
    return { exitCode: 1 };
  }
  if (process.platform !== 'darwin') {
    request.context.writeStderr('Xcode Simulator inspection is available only on macOS.\n');
    return { exitCode: 1 };
  }
  const runtimes = await scanXcodeRuntimesAsync();
  if (request.argv.includes('--json')) {
    request.context.writeStdout(`${JSON.stringify({ runtimes }, null, 2)}\n`);
  } else {
    for (const runtime of runtimes)
      request.context.writeStdout(
        `${runtime.family} ${runtime.name}: ${runtime.allocatedBytes ?? 'unknown'} allocated bytes; ${runtime.newestInstalled ? 'NEWEST INSTALLED' : 'older installed'}; active devices ${runtime.activeDeviceCount}; unavailable devices ${runtime.unavailableDeviceCount}\n`,
      );
  }
  return { exitCode: 0 };
}
