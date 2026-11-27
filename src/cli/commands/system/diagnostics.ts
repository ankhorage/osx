import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { runSystemDiagnostics } from './runSystemDiagnostics.js';

/*** Report available disk, SMART, and system-profile diagnostic samples. */
export async function diagnostics(
  request: AnkhCommandExecutionRequest,
): Promise<{ exitCode: number }> {
  return await runSystemDiagnostics(request, 'diagnostics');
}
