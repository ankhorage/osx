import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { runSystemDiagnostics } from './runSystemDiagnostics.js';

/*** Report a current process sample and separately labelled historical crash metadata. */
export async function processes(
  request: AnkhCommandExecutionRequest,
): Promise<{ exitCode: number }> {
  return await runSystemDiagnostics(request, 'processes');
}
