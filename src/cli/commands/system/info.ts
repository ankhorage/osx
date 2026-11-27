import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { runSystemDiagnostics } from './runSystemDiagnostics.js';

/*** Report read-only OS, build, and hardware facts when the host exposes them. */
export async function info(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  return await runSystemDiagnostics(request, 'info');
}
