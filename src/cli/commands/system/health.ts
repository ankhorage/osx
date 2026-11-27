import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { runSystemDiagnostics } from './runSystemDiagnostics.js';

/*** Report read-only memory, swap, and disk samples without assigning a health verdict. */
export async function health(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  return await runSystemDiagnostics(request, 'health');
}
