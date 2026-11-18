import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { createXcodeRuntimeOperations } from '../../../../features/xcode-runtimes/composition/createXcodeRuntimeOperations.js';

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
  const candidates = await createXcodeRuntimeOperations().scan();
  if (request.argv.includes('--json')) {
    request.context.writeStdout(`${JSON.stringify({ candidates }, null, 2)}\n`);
  } else {
    for (const candidate of candidates)
      request.context.writeStdout(
        `${candidate.label}: ${candidate.estimatedBytes ?? 'unknown'} allocated bytes; [${candidate.risk}] ${candidate.reason}\n${candidate.preview ? `${candidate.preview}\n` : ''}`,
      );
  }
  return { exitCode: 0 };
}
