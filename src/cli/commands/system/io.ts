import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { runSystemDiagnostics } from './runSystemDiagnostics.js';

/*** Report a bounded current I/O sample when the documented tool is available. */
export async function io(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  return await runSystemDiagnostics(request, 'io');
}
