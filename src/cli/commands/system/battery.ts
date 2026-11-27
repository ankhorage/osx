import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { runSystemDiagnostics } from './runSystemDiagnostics.js';

/*** Report read-only battery and thermal samples without assuming sensors are present. */
export async function battery(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  return await runSystemDiagnostics(request, 'battery');
}
