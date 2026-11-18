import type { AnkhCommandExecutionRequest } from '@ankhorage/ankh';

import { serializeSecurityAuditReport } from '../../../features/security-audit/application/serializeSecurityAuditReport.js';
import { createDefaultSecurityAuditReport } from '../../../features/security-audit/composition/createDefaultSecurityAuditReport.js';

/*** Render the currently available read-only audit boundary without inspecting or changing the host. */
export function audit(request: AnkhCommandExecutionRequest): Promise<{ exitCode: number }> {
  const expected = ['--non-interactive', '--json'];
  if (
    request.argv.length !== expected.length ||
    expected.some((argument) => !request.argv.includes(argument))
  ) {
    request.context.writeStderr('Usage: ankh osx security audit --non-interactive --json\n');
    return Promise.resolve({ exitCode: 1 });
  }
  request.context.writeStdout(serializeSecurityAuditReport(createDefaultSecurityAuditReport()));
  return Promise.resolve({ exitCode: 0 });
}
