import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { type SystemDiagnosticScope } from '../../../features/system-diagnostics/application/collectSystemDiagnosticsAsync.js';
import { collectDefaultSystemDiagnosticsAsync } from '../../../features/system-diagnostics/composition/collectDefaultSystemDiagnosticsAsync.js';

/*** Render one read-only system diagnostic scope as JSON without inferring unavailable evidence. */
export async function runSystemDiagnostics(
  request: Pick<AnkhCommandExecutionRequest, 'argv' | 'context'>,
  scope: SystemDiagnosticScope,
): Promise<{ exitCode: number }> {
  if (request.argv.length !== 0 && !(request.argv.length === 1 && request.argv[0] === '--json')) {
    request.context.writeStderr('Usage: ankh osx system <command> [--json]\n');
    return { exitCode: 1 };
  }
  request.context.writeStdout(
    `${JSON.stringify(await collectDefaultSystemDiagnosticsAsync(scope), null, 2)}\n`,
  );
  return { exitCode: 0 };
}
